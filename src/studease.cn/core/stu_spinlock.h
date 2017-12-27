/*
 * stu_spin.h
 *
 *  Created on: 2017年11月24日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_SPINLOCK_H_
#define STUDEASE_CN_CORE_STU_SPINLOCK_H_

#include "../stu_config.h"
#include "stu_core.h"

#define stu_spin_t          pthread_spinlock_t

#define stu_spin_init       pthread_spin_init
#define stu_spin_destroy    pthread_spin_destroy
#define stu_spin_trylock    pthread_spin_trylock
#define stu_spin_lock       pthread_spin_lock
#define stu_spin_unlock     pthread_spin_unlock

#endif /* STUDEASE_CN_CORE_STU_SPINLOCK_H_ */
