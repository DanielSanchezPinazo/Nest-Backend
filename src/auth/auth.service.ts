import { BadRequestException, Injectable, InternalServerErrorException, RequestTimeoutException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';

import * as bcryptjs from "bcryptjs";
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { LoginDto, RegisterUserDto, CreateUserDto, UpdateAuthDto } from './dto';
import { log } from 'console';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name )
    private userModel: Model<User>,
    private jwtService: JwtService
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {

    // 1- Encriptar la contraseña

      const { password, ...userData } =  createUserDto;

      const newUser = new this.userModel({

        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });

    // 2- Guardar el usuario

      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();

      return user;
    
    } catch( error )
      {

        if ( error.code === 11000 ) {

          throw new BadRequestException( `${ createUserDto.email } already exists!!` );
        }

        throw new InternalServerErrorException("Something terrible happen!!!");
      };
  };

  async register( registerUserDto: RegisterUserDto ): Promise<LoginResponse> {

    const user = await this.create( registerUserDto );
    // console.log( {user} );

    return {

      user: user,
      token: this.getJwtToken({ id: user._id })
    };
  };

  async login( loginDto: LoginDto ): Promise<LoginResponse> {

    const { email, password } = loginDto;
    
    // const user = await this.userModel.findOne({ email: email }); es lo mismo que lo de abajo
    const user = await this.userModel.findOne({ email });

    if ( !user ) {
      
      throw new UnauthorizedException( "not valid credentials - email" );
    };

    if ( !bcryptjs.compareSync( password, user.password )) {
      
      throw new UnauthorizedException( "not valid credentials - password" );
    };

    const { password:_, ...rest } = user.toJSON();

    return {

    // User { _id, name, email, roles }
    // Token -> ASDASD.ASDASDASD.ASDASDAS.

      user: rest,
      token: this.getJwtToken({ id: user.id })
    };
  };

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  // 3- Generar el JWT (Json Web Token)

  getJwtToken( payload: JwtPayload ) {

    const token = this.jwtService.sign( payload );
    return token;
  };
}
