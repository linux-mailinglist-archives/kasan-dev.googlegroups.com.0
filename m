Return-Path: <kasan-dev+bncBDUNBGN3R4KRBZEF7PEAMGQETEFSYTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 59444C72969
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 08:27:34 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-64174630bf9sf502261a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Nov 2025 23:27:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763623654; cv=pass;
        d=google.com; s=arc-20240605;
        b=CzVHl4Ec/h9JwyjJKTyJ3NHpkIKmu4e8AbW+Emqb3kJihp5iIrtTc4eB2reAJ4BZVz
         Fnzn9GaoO2eg9Yu18qPeTdNKPz1fmgROIjpfpsmDTJvGqMKDNUBvwwWND02h1AonKaIs
         sBypv7S/Ea94NTgE3NlqbR2RxkrkAuwoNU+qBtBnRunrEz/DNesStH0NK3Q8Q9X03siS
         j9mS/fG6mfar/r+ZUpUdLxtjrB7t1JdCrMNlU0ANG6MQYb58/dxTBxXS1PltkkSzQWJj
         KqQXV9CXaTchNUHHOWAOLtHdc+3NAJbrzGnnFaA7WEwLMcJxVFb18W9cnMj/MmuNOwEZ
         SlrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=V8NfXtI539gFLupXR7Bmo6YBmyumuY32ZjYSjAdkcQg=;
        fh=FTAH0mH3nGh6L260hq+p5CB5Ubj27q4/eE8/tCiOfqE=;
        b=JX8Bp4sTGMgge4rSIsr6OdMdqqWX++z8evwAAZgFYGlIgp/3jnEz4wEvSV99b0Ba03
         3ZpIw8sCh7emXGX1hWQXmqq2AxN4ShZwvsKT7T+9kcSTYskW/TU3ToEnY3jCO6ESEjdp
         +nCnaAEP7UECTmDuBEy1wawvxVYoD5T7C4AZInVW5IUTtlUtvylAIvaQyqXtQVT/q2Kb
         3gP/nlCjF2aEiIPbcVnSiZYbhMYjFoxWa3ogN5uO7BDLfSRHmqOSwCPSPz74BYcsEVxZ
         2AgMJSnbnK9uw9BkCLa0k0IzjRIxbrUG/fbpk+VBfZJx7NNorlQZR86MOL0meoszZ1Dw
         iZJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763623654; x=1764228454; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V8NfXtI539gFLupXR7Bmo6YBmyumuY32ZjYSjAdkcQg=;
        b=kI0Y3cEfXkFB+zNDZFA7lrYQnUo4R9JPXzQYk12vrdATscY5oT9z/ticOH9P87xh3o
         VEbSmGeORarBV8sODsC52Wrr5SQvA7uAKU3PM6FHFwrAdYUgUCEiwgUbf+5lfh+ewHr3
         HEaBIKBYMlB6zhjY8rk2SBnQN4/lG/fGW8vIcwf7fAO5qX8YlAi6HOt1isNulvVX0DD+
         TCjrbJtw6lk6P5KudhctiEFGiOLYgMmKQbSk7ivhtJDcH6B14afvSTRJkUpwhkUt4x9/
         nw9ZABnbYf+b/3gdLhjraamFsBtfaDeNksSnxyixPnWdm3Fxd08MSuKQD9UPEvjtrd3q
         pAsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763623654; x=1764228454;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=V8NfXtI539gFLupXR7Bmo6YBmyumuY32ZjYSjAdkcQg=;
        b=Z2emAV6Eayu/5X7ZPG8cNAAo8C0mj6y+VUEMvZVn+qjlOcrb7ReAzgmToeX58Sl8L4
         W9+c/2UJDNat6bO8Cq1pvuDj9EL3nBLGkTfREfwbco06KnT/amYJm1uTtJJHsnlGrGcD
         Kv0MyJXXZX+A7RgclEoWn+7lOVuyMv5iU4pY0gjcH1bdxzoqJuGl1q37yM/MrrmvZQD6
         HtWNiZVc1BmhUt0il0zPQDeEmEbs5/u8DjzlV7se7DbiI4zI7MqapLRCEcsFG/ByjXoc
         aSwJh032HYYG5cVy5pZT+8/eODbJRoeAiUBT0t+qJ1Cn70YS36bvT5BIuvtaeROpsqKG
         hqfw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsc0uVWg+8y2Pn3bIUH/UPExEYlZaVBU7Jl7g6LVI5vtMZKODOU/OA8nFnL3JS/jsWF+9ryA==@lfdr.de
X-Gm-Message-State: AOJu0YwXpJtdg+i0/fYnhlTqNQE5tTis1W1PCu9zHEZrm+xuSxvMsfji
	UfHejdsoljr3X5Bg7IR73QpVcYC7cEuXYqiuTgEro3JCMHwhoDKYOPW8
X-Google-Smtp-Source: AGHT+IEAgKbKyMF/xekM8Bn4CLyrCu4dzNBpSgoE0nuM1SdUmMs0AdAIhUffP+FB78Gs1azHATNNvw==
X-Received: by 2002:a05:6402:40d5:b0:640:c454:e8 with SMTP id 4fb4d7f45d1cf-6453648e0d9mr1986486a12.30.1763623653313;
        Wed, 19 Nov 2025 23:27:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZmrB6CJ1am+eNfKP745zfCh4sdCWLBcizVi+lfysNPcQ=="
Received: by 2002:a50:bac4:0:b0:643:8196:931 with SMTP id 4fb4d7f45d1cf-64536364f1dls537363a12.0.-pod-prod-09-eu;
 Wed, 19 Nov 2025 23:27:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVNm/10AojWgpArE2J0SD+JGHYww7xYBsMAJauhIK0lYY3BlAcESKOHclU/HHvxBPFlqRT3TQeoa6I=@googlegroups.com
X-Received: by 2002:a05:6402:1468:b0:643:e03:db04 with SMTP id 4fb4d7f45d1cf-6453641f228mr1925183a12.14.1763623650347;
        Wed, 19 Nov 2025 23:27:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763623650; cv=none;
        d=google.com; s=arc-20240605;
        b=EJSovvVR4Jgy0oviaXCXKbIJYhTwD6FkB9dWBDc2ydKHSx3saoEL0ijOGjfCtQ+KuV
         6Hi54l+aNL4IT6QcTmAdSXMvZgzDpwaEjaH7Gix5tEIaDREBsWk67N53DRRNrlUePXyE
         4Z7hRqvbPt99687B7bICT0UQyPKlX7z6Wa1vdJw6noO1fDhGJOKXLEo/+HVaAOJjeSs1
         v/GxZvmEeIUkSZ9CRFP1LwxynvenMWlugA3TN0ZfzsxhijrulseGz9CT1WmaVAzdhjd7
         mwsDfNGZ3rjrndBPCBzxtiXUknTh0vwElIE0ssihn5iRHp45FfkYdbQGiqSyZ7lJ3l0z
         sD/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=PeXopoGnVpa1AMUDs7beSLhVS8PFd0/tK69ottiollU=;
        fh=TfK3ISQDsfZx08iMAzQqY9LpaR+avMCrz5ryOqCTCR4=;
        b=Qi40B2/k058gEeimCDUCnjmnNxXo2Lr2qYT1jh2t/PCxjHSRekL1USDWUbJgrcUKIv
         NbYAhpxbu7bh4lNbOjKodAm+vLIe1kYuLoRiFPDfu7sdoB7gQ9R+66J2nT1htA46CTR2
         +bixG8jBi7GbOW5RuPsA+vBBcenvFGIh5oSmNIkz3e6tKCtijl+gDMOl5uuGr9/I3YjW
         H/GTuPd4dClKC4GqAnmArSe1OULj0XwhaB4960C8cYm2V53oB1081xAPJQSxyrI1/9HC
         szV06pbPpF7wThIUS5tOG6kFgnb5RPoDHNKmcklnuTQeIqkc0Y2L13/PQw+I49xCz2ND
         dOfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6453648cf50si39980a12.9.2025.11.19.23.27.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Nov 2025 23:27:30 -0800 (PST)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 0AA3C68B05; Thu, 20 Nov 2025 08:27:27 +0100 (CET)
Date: Thu, 20 Nov 2025 08:27:26 +0100
From: Christoph Hellwig <hch@lst.de>
To: kernel test robot <oliver.sang@intel.com>
Cc: Christoph Hellwig <hch@lst.de>, oe-lkp@lists.linux.dev, lkp@intel.com,
	Vlastimil Babka <vbabka@suse.cz>, linux-mm@kvack.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: Re: [linux-next:master] [mempool]  022e94e2c3:
 BUG:KASAN:double-free_in_mempool_free
Message-ID: <20251120072726.GA31171@lst.de>
References: <202511201309.55538605-lkp@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202511201309.55538605-lkp@intel.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Content-Transfer-Encoding: quoted-printable
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Maybe I'm misunderstanding the trace, but AFAICS this comes from
the KASAN kunit test that injects a double free, and the trace
shows that KASAN indeed detected the double free and everything is
fine.  Or did I misunderstand the report?

On Thu, Nov 20, 2025 at 01:57:20PM +0800, kernel test robot wrote:
>=20
>=20
> Hello,
>=20
> kernel test robot noticed "BUG:KASAN:double-free_in_mempool_free" on:
>=20
> commit: 022e94e2c304505973d00dedca4b1432c231fbf6 ("mempool: add mempool_{=
alloc,free}_bulk")
> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master
>=20
> [test failed on linux-next/master 187dac290bfd0741b9d7d5490af825c33fd9baa=
4]
>=20
> in testcase: kunit
> version:=20
> with following parameters:
>=20
> 	group: group-03
>=20
>=20
>=20
> config: x86_64-rhel-9.4-kunit
> compiler: gcc-14
> test machine: 8 threads 1 sockets Intel(R) Core(TM) i7-4770 CPU @ 3.40GHz=
 (Haswell) with 16G memory
>=20
> (please refer to attached dmesg/kmsg for entire log/backtrace)
>=20
>=20
>=20
> If you fix the issue in a separate patch/commit (i.e. not just a new vers=
ion of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202511201309.55538605-lkp@intel.=
com
>=20
>=20
> kern  :err   : [  152.903458] [   T4181] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D
> kern  :err   : [  152.916375] [   T4181] BUG: KASAN: double-free in mempo=
ol_free (mm/mempool.c:687 (discriminator 1))
> kern  :err   : [  152.922918] [   T4181] Free of addr ffff88812a92b800 by=
 task kunit_try_catch/4181
>=20
> kern  :err   : [  152.932343] [   T4181] CPU: 2 UID: 0 PID: 4181 Comm: ku=
nit_try_catch Tainted: G S  B            N  6.18.0-rc3-00007-g022e94e2c304 =
#1 PREEMPT(voluntary)
> kern  :err   : [  152.932348] [   T4181] Tainted: [S]=3DCPU_OUT_OF_SPEC, =
[B]=3DBAD_PAGE, [N]=3DTEST
> kern  :err   : [  152.932350] [   T4181] Hardware name: Dell Inc. OptiPle=
x 9020/0DNKMN, BIOS A05 12/05/2013
> kern  :err   : [  152.932351] [   T4181] Call Trace:
> kern  :err   : [  152.932353] [   T4181]  <TASK>
> kern  :err   : [  152.932354] [   T4181]  dump_stack_lvl (lib/dump_stack.=
c:122)
> kern  :err   : [  152.932358] [   T4181]  print_address_description+0x88/=
0x320
> kern  :err   : [  152.932362] [   T4181]  print_report (mm/kasan/report.c=
:483)
> kern  :err   : [  152.932365] [   T4181]  ? mempool_free (mm/mempool.c:68=
7 (discriminator 1))
> kern  :err   : [  152.932367] [   T4181]  kasan_report_invalid_free (mm/k=
asan/report.c:563)
> kern  :err   : [  152.932371] [   T4181]  ? mempool_free (mm/mempool.c:68=
7 (discriminator 1))
> kern  :err   : [  152.932374] [   T4181]  ? mempool_free (mm/mempool.c:68=
7 (discriminator 1))
> kern  :err   : [  152.932376] [   T4181]  ? mempool_free (mm/mempool.c:68=
7 (discriminator 1))
> kern  :err   : [  152.932378] [   T4181]  check_slab_allocation (mm/kasan=
/common.c:230)
> kern  :err   : [  152.932381] [   T4181]  __kasan_mempool_poison_object (=
mm/kasan/common.c:542 (discriminator 1))
> kern  :err   : [  152.932384] [   T4181]  mempool_free_bulk (mm/mempool.c=
:137 mm/mempool.c:160 mm/mempool.c:653)
> kern  :err   : [  152.932387] [   T4181]  ? mempool_init_node (mm/mempool=
.c:140 mm/mempool.c:160 mm/mempool.c:245)
> kern  :err   : [  152.932389] [   T4181]  ? _raw_spin_lock_irqsave (arch/=
x86/include/asm/atomic.h:107 (discriminator 4) include/linux/atomic/atomic-=
arch-fallback.h:2170 (discriminator 4) include/linux/atomic/atomic-instrume=
nted.h:1302 (discriminator 4) include/asm-generic/qspinlock.h:111 (discrimi=
nator 4) include/linux/spinlock.h:187 (discriminator 4) include/linux/spinl=
ock_api_smp.h:111 (discriminator 4) kernel/locking/spinlock.c:162 (discrimi=
nator 4))
> kern  :err   : [  152.932393] [   T4181]  mempool_free (mm/mempool.c:687 =
(discriminator 1))
> kern  :err   : [  152.932395] [   T4181]  ? __pfx_mempool_free (mm/mempoo=
l.c:686)
> kern  :err   : [  152.932398] [   T4181]  ? kasan_save_track (mm/kasan/co=
mmon.c:69 (discriminator 1) mm/kasan/common.c:78 (discriminator 1))
> kern  :err   : [  152.932400] [   T4181]  ? remove_element (mm/mempool.c:=
172)
> kern  :err   : [  152.932414] [   T4181] mempool_double_free_helper (mm/k=
asan/kasan_test_c.c:1444 (discriminator 17)) kasan_test
> kern  :err   : [  152.932423] [   T4181]  ? __pfx_mempool_double_free_hel=
per (mm/kasan/kasan_test_c.c:1436) kasan_test
> kern  :err   : [  152.932440] [   T4181]  ? sched_clock (arch/x86/include=
/asm/preempt.h:95 arch/x86/kernel/tsc.c:289)
> kern  :err   : [  152.932442] [   T4181]  ? __update_idle_core (kernel/sc=
hed/sched.h:1340 kernel/sched/fair.c:7584)
> kern  :err   : [  152.932445] [   T4181] mempool_kmalloc_double_free (mm/=
kasan/kasan_test_c.c:1457) kasan_test
> kern  :err   : [  152.932453] [   T4181]  ? __pfx_mempool_kmalloc_double_=
free (mm/kasan/kasan_test_c.c:1448) kasan_test
> kern  :err   : [  152.932461] [   T4181]  ? __switch_to (arch/x86/include=
/asm/cpufeature.h:101 arch/x86/kernel/process_64.c:378 arch/x86/kernel/proc=
ess_64.c:666)
> kern  :err   : [  152.932463] [   T4181]  ? __pfx_mempool_kmalloc (mm/mem=
pool.c:715)
> kern  :err   : [  152.932466] [   T4181]  ? __pfx_mempool_kfree (mm/mempo=
ol.c:722)
> kern  :err   : [  152.932468] [   T4181]  ? __pfx_read_tsc (arch/x86/incl=
ude/asm/tsc.h:57 arch/x86/kernel/tsc.c:1134)
> kern  :err   : [  152.932471] [   T4181]  ? ktime_get_ts64 (kernel/time/t=
imekeeping.c:387 kernel/time/timekeeping.c:404 kernel/time/timekeeping.c:96=
7)
> kern  :err   : [  152.932474] [   T4181]  ? __pfx___schedule (kernel/sche=
d/core.c:6785)
> kern  :err   : [  152.932477] [   T4181]  kunit_try_run_case (lib/kunit/t=
est.c:450 lib/kunit/test.c:493)
> kern  :err   : [  152.932480] [   T4181]  ? __pfx_kunit_try_run_case (lib=
/kunit/test.c:480)
> kern  :err   : [  152.932483] [   T4181]  ? _raw_spin_lock_irqsave (arch/=
x86/include/asm/atomic.h:107 (discriminator 4) include/linux/atomic/atomic-=
arch-fallback.h:2170 (discriminator 4) include/linux/atomic/atomic-instrume=
nted.h:1302 (discriminator 4) include/asm-generic/qspinlock.h:111 (discrimi=
nator 4) include/linux/spinlock.h:187 (discriminator 4) include/linux/spinl=
ock_api_smp.h:111 (discriminator 4) kernel/locking/spinlock.c:162 (discrimi=
nator 4))
> kern  :err   : [  152.932486] [   T4181]  ? __pfx__raw_spin_lock_irqsave =
(kernel/locking/spinlock.c:161)
> kern  :err   : [  152.932489] [   T4181]  ? __pfx__raw_spin_lock_irqsave =
(kernel/locking/spinlock.c:161)
> kern  :err   : [  152.932492] [   T4181]  ? __pfx_kunit_try_run_case (lib=
/kunit/test.c:480)
> kern  :err   : [  152.932494] [   T4181]  ? __pfx_kunit_generic_run_threa=
dfn_adapter (lib/kunit/try-catch.c:26)
> kern  :err   : [  152.932498] [   T4181]  kunit_generic_run_threadfn_adap=
ter (lib/kunit/try-catch.c:31)
> kern  :err   : [  152.932501] [   T4181]  kthread (kernel/kthread.c:463)
> kern  :err   : [  152.932503] [   T4181]  ? __pfx_kthread (kernel/kthread=
.c:412)
> kern  :err   : [  152.932505] [   T4181]  ? __pfx__raw_spin_lock_irq (ker=
nel/locking/spinlock.c:169)
> kern  :err   : [  152.932509] [   T4181]  ? __pfx_kthread (kernel/kthread=
.c:412)
> kern  :err   : [  152.932511] [   T4181]  ? __pfx_kthread (kernel/kthread=
.c:412)
> kern  :err   : [  152.932513] [   T4181]  ret_from_fork (arch/x86/kernel/=
process.c:164)
> kern  :err   : [  152.932516] [   T4181]  ? __pfx_kthread (kernel/kthread=
.c:412)
> kern  :err   : [  152.932518] [   T4181]  ret_from_fork_asm (arch/x86/ent=
ry/entry_64.S:255)
> kern  :err   : [  152.932522] [   T4181]  </TASK>
>=20
> kern  :err   : [  153.201368] [   T4181] Allocated by task 4181:
> kern  :warn  : [  153.205558] [   T4181]  kasan_save_stack (mm/kasan/comm=
on.c:57)
> kern  :warn  : [  153.210098] [   T4181]  kasan_save_track (mm/kasan/comm=
on.c:69 (discriminator 1) mm/kasan/common.c:78 (discriminator 1))
> kern  :warn  : [  153.214637] [   T4181]  remove_element (mm/mempool.c:17=
2)
> kern  :warn  : [  153.219176] [   T4181]  mempool_alloc_preallocated (inc=
lude/linux/spinlock.h:406 mm/mempool.c:409 mm/mempool.c:585)
> kern  :warn  : [  153.224582] [   T4181] mempool_double_free_helper (mm/k=
asan/kasan_test_c.c:1439) kasan_test
> kern  :warn  : [  153.231213] [   T4181] mempool_kmalloc_double_free (mm/=
kasan/kasan_test_c.c:1457) kasan_test
> kern  :warn  : [  153.237839] [   T4181]  kunit_try_run_case (lib/kunit/t=
est.c:450 lib/kunit/test.c:493)
> kern  :warn  : [  153.242727] [   T4181]  kunit_generic_run_threadfn_adap=
ter (lib/kunit/try-catch.c:31)
> kern  :warn  : [  153.248830] [   T4181]  kthread (kernel/kthread.c:463)
> kern  :warn  : [  153.252759] [   T4181]  ret_from_fork (arch/x86/kernel/=
process.c:164)
> kern  :warn  : [  153.257211] [   T4181]  ret_from_fork_asm (arch/x86/ent=
ry/entry_64.S:255)
>=20
> kern  :err   : [  153.264025] [   T4181] Freed by task 4181:
> kern  :warn  : [  153.267866] [   T4181]  kasan_save_stack (mm/kasan/comm=
on.c:57)
> kern  :warn  : [  153.272416] [   T4181]  kasan_save_track (mm/kasan/comm=
on.c:69 (discriminator 1) mm/kasan/common.c:78 (discriminator 1))
> kern  :warn  : [  153.276964] [   T4181]  __kasan_save_free_info (mm/kasa=
n/generic.c:590 (discriminator 1))
> kern  :warn  : [  153.282025] [   T4181]  __kasan_mempool_poison_object (=
mm/kasan/common.c:534)
> kern  :warn  : [  153.287868] [   T4181]  mempool_free_bulk (mm/mempool.c=
:137 mm/mempool.c:160 mm/mempool.c:653)
> kern  :warn  : [  153.292668] [   T4181]  mempool_free (mm/mempool.c:687 =
(discriminator 1))
> kern  :warn  : [  153.296944] [   T4181] mempool_double_free_helper (mm/k=
asan/kasan_test_c.c:1444 (discriminator 5)) kasan_test
> kern  :warn  : [  153.303573] [   T4181] mempool_kmalloc_double_free (mm/=
kasan/kasan_test_c.c:1457) kasan_test
> kern  :warn  : [  153.310203] [   T4181]  kunit_try_run_case (lib/kunit/t=
est.c:450 lib/kunit/test.c:493)
> kern  :warn  : [  153.315091] [   T4181]  kunit_generic_run_threadfn_adap=
ter (lib/kunit/try-catch.c:31)
> kern  :warn  : [  153.321198] [   T4181]  kthread (kernel/kthread.c:463)
> kern  :warn  : [  153.325127] [   T4181]  ret_from_fork (arch/x86/kernel/=
process.c:164)
> kern  :warn  : [  153.329576] [   T4181]  ret_from_fork_asm (arch/x86/ent=
ry/entry_64.S:255)
>=20
> kern  :err   : [  153.336387] [   T4181] The buggy address belongs to the=
 object at ffff88812a92b800
> which belongs to the cache kmalloc-128 of size 128
> kern  :err   : [  153.350320] [   T4181] The buggy address is located 0 b=
ytes inside of
> 128-byte region [ffff88812a92b800, ffff88812a92b880)
>=20
> kern  :err   : [  153.365488] [   T4181] The buggy address belongs to the=
 physical page:
> kern  :warn  : [  153.371765] [   T4181] page: refcount:0 mapcount:0 mapp=
ing:0000000000000000 index:0x0 pfn:0x12a92a
> kern  :warn  : [  153.380478] [   T4181] head: order:1 mapcount:0 entire_=
mapcount:0 nr_pages_mapped:0 pincount:0
> kern  :warn  : [  153.388842] [   T4181] flags: 0x17ffffc0000040(head|nod=
e=3D0|zone=3D2|lastcpupid=3D0x1fffff)
> kern  :warn  : [  153.396513] [   T4181] page_type: f5(slab)
> kern  :warn  : [  153.400355] [   T4181] raw: 0017ffffc0000040 ffff888100=
042a00 ffffea00040b9600 0000000000000004
> kern  :warn  : [  153.408806] [   T4181] raw: 0000000000000000 0000000080=
200020 00000000f5000000 0000000000000000
> kern  :warn  : [  153.417258] [   T4181] head: 0017ffffc0000040 ffff88810=
0042a00 ffffea00040b9600 0000000000000004
> kern  :warn  : [  153.425800] [   T4181] head: 0000000000000000 000000008=
0200020 00000000f5000000 0000000000000000
> kern  :warn  : [  153.434338] [   T4181] head: 0017ffffc0000001 ffffea000=
4aa4a81 00000000ffffffff 00000000ffffffff
> kern  :warn  : [  153.442876] [   T4181] head: ffffffffffffffff 000000000=
0000000 00000000ffffffff 0000000000000002
> kern  :warn  : [  153.451422] [   T4181] page dumped because: kasan: bad =
access detected
>=20
> kern  :err   : [  153.459902] [   T4181] Memory state around the buggy ad=
dress:
> kern  :err   : [  153.465395] [   T4181]  ffff88812a92b700: fa fb fb fb f=
b fb fb fb fb fb fb fb fb fb fb fb
> kern  :err   : [  153.473335] [   T4181]  ffff88812a92b780: fc fc fc fc f=
c fc fc fc fc fc fc fc fc fc fc fc
> kern  :err   : [  153.481266] [   T4181] >ffff88812a92b800: fa fb fb fb f=
b fb fb fb fb fb fb fb fb fb fb fb
> kern  :err   : [  153.489195] [   T4181]                    ^
> kern  :err   : [  153.493121] [   T4181]  ffff88812a92b880: fc fc fc fc f=
c fc fc fc fc fc fc fc fc fc fc fc
> kern  :err   : [  153.501051] [   T4181]  ffff88812a92b900: fa fb fb fb f=
b fb fb fb fb fb fb fb fb fb fb fb
> kern  :err   : [  153.508980] [   T4181] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D
> kern  :info  : [  153.517054] [   T3993]     ok 51 mempool_kmalloc_double=
_free
> kern  :err   : [  153.517141] [   T4183] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D
>=20
>=20
> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20251120/202511201309.55538605-lk=
p@intel.com
>=20
>=20
>=20
> --=20
> 0-DAY CI Kernel Test Service
> https://github.com/intel/lkp-tests/wiki
---end quoted text---

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251120072726.GA31171%40lst.de.
