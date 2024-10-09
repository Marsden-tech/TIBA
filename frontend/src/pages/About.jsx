import React from 'react'
import { assets } from '../assets/assets'

const About = () => {
  return (
    <div>

      <div className='text-center text-2xl pt-10 text-gray-500'>
        <p>ABOUT <span className='text-gray-700 font-medium'>US</span></p>
      </div>

      <div className='my-10 flex flex-col md:flex-row gap-12'>
        <img className='w-full md:max-w-[360px]' src={assets.about_image} alt='' />
        <div className='flex flex-col justify-center gap-6 md:w-2/4 text-sm text-gray-600'>
          <p>Lorem ipsum dolor sit amet consectetur adipisicing elit. Praesentium animi similique accusantium distinctio harum quibusdam quasi magni dicta atque? Ipsam eligendi facere, aspernatur perspiciatis cum sint, obcaecati incidunt temporibus, nisi consequatur quidem labore voluptas pariatur esse minima a fuga! At error totam sint dolor quo atque, dicta veritatis quis voluptatibus?</p>
          <p>Lorem, ipsum dolor sit amet consectetur adipisicing elit. Natus cupiditate, ex magni nesciunt nulla odit, voluptatem earum cumque quasi consequuntur nostrum dolor doloribus tenetur ullam doloremque excepturi molestias in. Doloribus exercitationem veritatis qui quisquam amet ipsa libero voluptas inventore quam!</p>
          <b className='text-gray-800'>Vision</b>
          <p>Lorem, ipsum dolor sit amet consectetur adipisicing elit. Nemo tempore officiis itaque consequatur odio obcaecati debitis, est a esse, reiciendis iusto nisi. At quis reprehenderit molestias voluptates delectus, accusantium nesciunt?</p>
        </div>
      </div>

      <div className='text-xl my-4'>
        <p>WHY <span className='text-gray-700 font-semibold'>BOOK WITH US</span> </p>
      </div>

      <div className='flex flex-col md:flex-row mb-20'>
        <div className='border px-10 md:px-16 py-8 sm:py-16 flex flex-col gap-5 text-[15px] hover:bg-primary hover:text-white transition-all duration-300 text-gray-600 cursor-pointer'>
          <b>Efficiency:</b>
          <p>Seamless appointment scheduling that fits perfect into your busy schedules.</p>
        </div>
        <div className='border px-10 md:px-16 py-8 sm:py-16 flex flex-col gap-5 text-[15px] hover:bg-primary hover:text-white transition-all duration-300 text-gray-600 cursor-pointer'>
          <b>Convenience:</b>
          <p>Access to a wide network of quality and trusted healthcare professionals</p>
        </div>
        <div className='border px-10 md:px-16 py-8 sm:py-16 flex flex-col gap-5 text-[15px] hover:bg-primary hover:text-white transition-all duration-300 text-gray-600 cursor-pointer'> 
          <b>Personalization:</b>
          <p>Use of recommendations and reminders to help you keep track and stay on top of your health</p>
        </div>
      </div>

    </div>
  )
}

export default About