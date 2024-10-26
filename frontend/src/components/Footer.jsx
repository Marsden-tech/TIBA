import React from 'react'
import { assets } from '../assets/assets'

const Footer = () => {
  return (
    <div className='md:mx-10'>
        <div className='flex flex-col sm:grid grid-cols-[3fr_1fr_1fr] gap-14 my-10 mt-40 text-sm'>
            {/* ----- Left section -----*/}
            <div>
                <img className='mb-5 w-39 h-16' src={assets.tiba_logo} alt='' />
                <p className='w-full md:w-2/3 text-gray-600 leading-6'>Lorem, ipsum dolor sit amet consectetur adipisicing elit. Eos, consectetur. Mollitia possimus inventore quas debitis vitae nesciunt consequatur deserunt similique, assumenda porro qui unde voluptate quos iusto totam voluptatibus optio delectus labore adipisci ea sunt eius? Earum nemo consequatur ducimus.</p>
            </div>

            {/* ----- Middle section -----*/}
            <div>
                <p className='text-xl font-medium mb-5'>WEBSITE</p>
                <ul className='flex flex-col gap-2 text-gray-600'>
                    <li>Home</li>
                    <li>About</li>
                    <li>Contact us</li>
                </ul> 
            </div>

            {/* ----- Right section -----*/}
            <div>
                <p className='text-xl font-medium mb-5'>GET IN TOUCH</p>
                <ul className='flex flex-col gap-2 text-gray-600'>
                    <li>+254 711-111-111</li>
                    <li>tiba@gmail.com</li>
                </ul>
            </div>
        </div>

        {/* ----- Copyright Text -----*/}
        <div>
            <hr />
            <p className='py-5 text-sm text-center'>Copyright @2024 TIBA</p>
        </div>
    </div>
  )
}

export default Footer