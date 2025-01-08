Return-Path: <kasan-dev+bncBDW2JDUY5AORB2OD7K5QMGQEYVG7M4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id F3DDFA0610B
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2025 17:03:55 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-53faf9e6195sf473342e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2025 08:03:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736352235; cv=pass;
        d=google.com; s=arc-20240605;
        b=J/mnJ20+vcJygnFpThmauc37uGHuA0ONDPtRqvaikIR5le2MiM1Z2r+/yJwQj3nBE4
         C2HIunwp7JP7fMKs2ar1/ooMUqnJmKr/oWJxxPHZK5Cunzo/M6D6t06IAe+6QQN+908i
         cOS5KhiR6ya3ZGMYUlYggAVt1HMAzweh8cJ/1Pt7SkI7vp7PFPYB439sxhUSeQDI/yjA
         etkGL8hsuWHDIs56+G/QB69O2F9uOiz6152k+QZFWImSJFw6zSM8aPolnaaCFN8gM50Z
         f2vbTCa9o1N/tdTcBfxDQ/Xdh4RM+AuCtl3UMPpRa5c+UBNI9v+Ey8xRbWNlCJMwohGq
         EIOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ReL2zXNnEYCFIERtSjzsYLUEgLynW3Xm6n34+lw/QLg=;
        fh=NYG/ZnMrVgj2MUlE9sacoWzz35d+bHMfxonPpLdnaRA=;
        b=adaMvUKkuMUEgLjUKWuJQbhL2y7nrnnd9feOicFMSmFnXmx9jleUzTyyaqULk6LWt2
         ZyAoLjyx2uGq3HXy1870D0OOuaTMqZvNogWsAWxhuSYKScBsHbMw3DQ/4T51j9tdixLp
         Dnx03wQWLzhvbbioNcwW875fBmjV7go7jkaJoEqRaLeVswc/fDd0x9Xr1PAgQTChFn6y
         TvqAfLUcoA1eqduMnTVYceC+tMLq9iRHYqdDM2Fb1XcPHGlxjNNyFavnl4giHbR5CxpQ
         muzZuy7UYwV2s4RyrwT0zkiorkQy5CkeZz4JGgY2tsPSvgap2dTqPQcWzkVK05TS2XDA
         a8RQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U9jkH4Ab;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736352235; x=1736957035; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ReL2zXNnEYCFIERtSjzsYLUEgLynW3Xm6n34+lw/QLg=;
        b=iMLY6pTZ7JOP/Wmz4TRSv374V/1vd27VLj1suEn0jnK3ak9HDpwAE1zs+calTzJe5H
         nz1zfLpOdeE1nhE5qaKZ73VzkT/XzcFcQj2jgfQMuegGHi8czYdavvY5Ry4NYSQVwJmN
         lhXrqBV0DLH8C2/6SiVNgL24bDdpI8cUc7KvCpZESnLLO6TEKyeBfpN+5AgfctnuHZMV
         gp1hKMefa6hPtGNMaXZ3XHRzY8+Jg2uqGQhAeFoIzSsbhs+PcJwZlunTUhn85OCJWiMC
         dSHOF/3TEhGRcQ1qbH3ZQPn0b+n+jOeUdNCm5PKqXZIfRCRG1EhNSlm1EZFrDV8irPx2
         y5cw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1736352235; x=1736957035; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ReL2zXNnEYCFIERtSjzsYLUEgLynW3Xm6n34+lw/QLg=;
        b=C/K4y1IzkPyH6timIcuZNRfqtNgbwmq3wIe2qnNMjntuHwiLPcLkZXiiUgem0lH6iJ
         dsS7neYy+VtJkDfj2AatCuh7872lyPMFBI4RFvRjnGUaXYm6eSfaQHhRQRH76cPepQ51
         1gBytobQyHgUtRrxRjaYzQL09mhddboN6rKBpGHeWCrJyol4SUvQFesqPc5sA9vcCpdM
         km12oZh2hP9genxuplIQ1ehEKitZRGo5c+5diVWyUyhM1CXQt80Sm/QTIKqwEZT0U9BH
         2UTEPvihKITWowOngVqUzh6PBkQOKfDixhF2e41Rc6VdDU1YKvfMNfJ0aj+tBKYtW9dD
         kRIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736352235; x=1736957035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ReL2zXNnEYCFIERtSjzsYLUEgLynW3Xm6n34+lw/QLg=;
        b=bBnWgnNTnMeGzpPbOngPgBGLntlUgrtGMzz+OUzcUB5HjzzTRRRyZkr8DS17yEVxUv
         OT7EpwUMyG1YH0VGUCSvL7jk9ZMdlOP4XDfDWPoZB2FYQACBSpR5Jh4f3rF4o7atetIy
         ReAgMtRY6w4+fhfnxtkIia6dyE0RpzayaFu+m6z5IR4NAnMmFRjj8OL/xxyYAhVKGKBL
         q5LREEoavEnHzjREGFfTeFrK53sMg3xly509P6ot7tXAV+TGURzhTQ6YEO+E4HwbRZZS
         aW6a+YvEzS5pesVyngRxCmSlSdQHGNkGiccEk1BxrCDEUu9nzHybGbchvDdNLlFPU5CI
         cKuQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTmthpGNqjO+2C1dDs2StFRBrGZ3fpN8i0SSpwbPsgcvfn6Yliz4UZYDqmPlEXe1U3VBxTPQ==@lfdr.de
X-Gm-Message-State: AOJu0YxRc2yJAYJBXhOBhz7F3z/ioVnLU8mRZUaOYez344p70d1mQcwS
	9PUkl3UlwX89uVvEgZqwvVMmp2ULY9Yc5XWTgRs0boCV6dQxo+GY
X-Google-Smtp-Source: AGHT+IGdCa2xx81o4a72oVAUDEPhhZzmfaL0pPsl6bZAzXunRmdol/T/X+1Sp3owhhj5NbBfERzMrA==
X-Received: by 2002:a05:6512:318b:b0:541:3196:2efd with SMTP id 2adb3069b0e04-5427e9762b7mr2179846e87.10.1736352234285;
        Wed, 08 Jan 2025 08:03:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6454:0:b0:540:1786:f554 with SMTP id 2adb3069b0e04-5425ddf1112ls90903e87.1.-pod-prod-00-eu;
 Wed, 08 Jan 2025 08:03:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnhvSGzazmNu7Jnva9Cozx3INXdc86vHoRS4oLDPll7yW5focPPil7AytJpCKbKYjcQ45HV9PlAHo=@googlegroups.com
X-Received: by 2002:a05:6512:1287:b0:540:2d60:d6ce with SMTP id 2adb3069b0e04-5427e9ca4f9mr2341256e87.24.1736352231699;
        Wed, 08 Jan 2025 08:03:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736352231; cv=none;
        d=google.com; s=arc-20240605;
        b=OQRsBfiqD2493jg4Xs98PWsMUw9tUc6ycenVTVOnjGIw/5W8uCble0A91VyBhvsnkJ
         88MgwVc9xAH3F2f8OqJaJDZpoBNa4G7WkM0YPEpgBtLNCCk1sc5s4NXFhWw1B0CSrAUi
         husmkSoe80OoGO7eBP8FEoMWPty4fA23YxLJpwxaiLCdYWT26SH58q3gV2zWViZwvmzR
         aLHgaNalhxI06430U4hUmswfrlyFf9gavPSgRCX53AN9f/+EJ6+PSef/YZJPXZQvtwdr
         OMCVzfB97N/sOEB7d9+Wwjyp9hRS0W2pPTIrIiHRRf0u59iT32VLJ3u1QkKviv5fCnpq
         xH8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+bC+1J5q7xH7BokG/eMvPi3f8aneMsQgO05LeT7Gf8c=;
        fh=o1+120NhSNiQrBgZPtoeeiCt9wgO2+GprD1m/0QvlM4=;
        b=IRkSi6iulhVMdtgGllRtyJ6SfDdZvraKndVdz+QaXZm/mrUQ+yJhGeTTXYt0RZza/9
         fyrzk/eBlk7qEKUNQaXIsB/9bvc+vH7swuSAGAq+CtyO7YlwyRpNYCMxjQi2VXLLwyBD
         nZvQ+3w/4dGoRLV54DGqqCF+/NadyMof3fUQlaaYP8dVAu0S7G4iCo15RGKIFIVWJkmP
         1IQfNZWiXeJ3Oba93IsG9/ge4TjaOgAO4a1KOkp7tHsIDmQFZMsGLm0TDlOhucCuvcyC
         BnWlyUSd4gqs4TxXf4bj4+ib0V5OcYfYZ25mdVD4P1fnlASn1MkgRTgc35fqSnXoxSOa
         yXgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U9jkH4Ab;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-542235eb716si844563e87.2.2025.01.08.08.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Jan 2025 08:03:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-3862b364538so640819f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 08 Jan 2025 08:03:51 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWl+zhx0jViWMwS3f8gKP4bmO2gNqydu7TH4nV8mJOdT3xJd9YhCNZGpIPvBrsWxdiJPnU/cC1ieA4=@googlegroups.com
X-Gm-Gg: ASbGncv9k1VM4JkdOfKmHPcLSkVAZa0A+yhiipkL3shbKEMkwi+081aAu1BMd/4kg8r
	pzS5VSTl0x+qTHej+5xL7ezAW1cyaDikMlB+nzNzN
X-Received: by 2002:a5d:64c4:0:b0:385:e90a:b7de with SMTP id
 ffacd0b85a97d-38a85e1f125mr3113087f8f.5.1736352230257; Wed, 08 Jan 2025
 08:03:50 -0800 (PST)
MIME-Version: 1.0
References: <202501081209.b7d8b735-lkp@intel.com>
In-Reply-To: <202501081209.b7d8b735-lkp@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 8 Jan 2025 17:03:39 +0100
X-Gm-Features: AbW1kvYrk6efBY20yW0ikchoAZJf9YHw-oweGsE9JlJb_0wX1vuj8CHuedrBkjM
Message-ID: <CA+fCnZfkMuk8dtk+5_7DK_h0Pxv_JNgJDL3D-8pBXOByzVOtzQ@mail.gmail.com>
Subject: Re: [linus:master] [kasan] 3738290bfc: kunit.kasan.fail
To: kernel test robot <oliver.sang@intel.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>
Cc: Nihar Chaithanya <niharchaithanya@gmail.com>, oe-lkp@lists.linux.dev, lkp@intel.com, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=U9jkH4Ab;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Jan 8, 2025 at 8:04=E2=80=AFAM kernel test robot <oliver.sang@intel=
.com> wrote:
>
>
>
> Hello,
>
>
> we found the new added test kmalloc_track_caller_oob_right randomly faile=
d
> (10 out of 30 runs) which seems due to below (1)
>
> 1857099c18e16a72 3738290bfc99606787f515a4590
> ---------------- ---------------------------
>        fail:runs  %reproduction    fail:runs
>            |             |             |
>            :30          33%          10:30    kunit.kasan.fail
>            :30          33%          10:30    dmesg.BUG:KFENCE:memory_cor=
ruption_in_kmalloc_track_caller_oob_right <-- (1)
>
> below are details.
>
>
> kernel test robot noticed "kunit.kasan.fail" on:
>
> commit: 3738290bfc99606787f515a4590ad38dc4f79ca4 ("kasan: add kunit tests=
 for kmalloc_track_caller, kmalloc_node_track_caller")
> https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master
>
> [test failed on linus/master      0bc21e701a6ffacfdde7f04f87d664d82e8a13b=
f]
> [test failed on linux-next/master 8155b4ef3466f0e289e8fcc9e6e62f3f4dceeac=
2]
>
> in testcase: kunit
> version:
> with following parameters:
>
>         group: group-03
>
>
>
> config: x86_64-rhel-9.4-kunit
> compiler: gcc-12
> test machine: 8 threads 1 sockets Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz=
 (Kaby Lake) with 32G memory
>
> (please refer to attached dmesg/kmsg for entire log/backtrace)
>
>
>
>
> If you fix the issue in a separate patch/commit (i.e. not just a new vers=
ion of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202501081209.b7d8b735-lkp@intel.=
com
>
>
>
> [  117.724741]     ok 3 kmalloc_node_oob_right
> [  117.724849] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [  117.737591] BUG: KASAN: slab-out-of-bounds in kmalloc_track_caller_oob=
_right+0x4ca/0x530 [kasan_test]
> [  117.747467] Write of size 1 at addr ffff888165906078 by task kunit_try=
_catch/3613
>
> [  117.757782] CPU: 7 UID: 0 PID: 3613 Comm: kunit_try_catch Tainted: G  =
  B   W        N 6.12.0-rc6-00221-g3738290bfc99 #1
> [  117.769291] Tainted: [B]=3DBAD_PAGE, [W]=3DWARN, [N]=3DTEST
> [  117.775007] Hardware name: Dell Inc. OptiPlex 7050/062KRH, BIOS 1.2.0 =
12/22/2016
> [  117.783056] Call Trace:
> [  117.786185]  <TASK>
> [  117.788966]  dump_stack_lvl+0x4f/0x70
> [  117.793307]  print_address_description.constprop.0+0x2c/0x3a0
> [  117.799721]  ? kmalloc_track_caller_oob_right+0x4ca/0x530 [kasan_test]
> [  117.806918]  print_report+0xb9/0x280
> [  117.811183]  ? kasan_addr_to_slab+0x9/0x90
> [  117.815961]  ? kmalloc_track_caller_oob_right+0x4ca/0x530 [kasan_test]
> [  117.823154]  kasan_report+0xcb/0x100
> [  117.827408]  ? kmalloc_track_caller_oob_right+0x4ca/0x530 [kasan_test]
> [  117.834602]  kmalloc_track_caller_oob_right+0x4ca/0x530 [kasan_test]
> [  117.841626]  ? __pfx_kmalloc_track_caller_oob_right+0x10/0x10 [kasan_t=
est]
> [  117.849166]  ? __schedule+0x716/0x15e0
> [  117.853589]  ? ktime_get_ts64+0x7f/0x240
> [  117.858186]  kunit_try_run_case+0x173/0x440
> [  117.863043]  ? try_to_wake_up+0x913/0x1580
> [  117.867813]  ? __pfx_kunit_try_run_case+0x10/0x10
> [  117.873187]  ? __pfx__raw_spin_lock_irqsave+0x10/0x10
> [  117.878915]  ? set_cpus_allowed_ptr+0x81/0xb0
> [  117.883956]  ? __pfx_set_cpus_allowed_ptr+0x10/0x10
> [  117.889502]  ? __pfx_kunit_try_run_case+0x10/0x10
> [  117.894876]  ? __pfx_kunit_generic_run_threadfn_adapter+0x10/0x10
> [  117.901633]  kunit_generic_run_threadfn_adapter+0x79/0xe0
> [  117.907698]  kthread+0x2d4/0x3c0
> [  117.911604]  ? __pfx_kthread+0x10/0x10
> [  117.916032]  ret_from_fork+0x2d/0x70
> [  117.920291]  ? __pfx_kthread+0x10/0x10
> [  117.924718]  ret_from_fork_asm+0x1a/0x30
> [  117.929324]  </TASK>
>
> [  117.934373] Allocated by task 3613:
> [  117.938544]  kasan_save_stack+0x1c/0x40
> [  117.943062]  kasan_save_track+0x10/0x30
> [  117.947574]  __kasan_kmalloc+0xa6/0xb0
> [  117.951998]  __kmalloc_node_track_caller_noprof+0x1bd/0x470
> [  117.958239]  kmalloc_track_caller_oob_right+0x8c/0x530 [kasan_test]
> [  117.965176]  kunit_try_run_case+0x173/0x440
> [  117.970031]  kunit_generic_run_threadfn_adapter+0x79/0xe0
> [  117.976097]  kthread+0x2d4/0x3c0
> [  117.980000]  ret_from_fork+0x2d/0x70
> [  117.984251]  ret_from_fork_asm+0x1a/0x30
>
> [  117.991022] The buggy address belongs to the object at ffff88816590600=
0
>                 which belongs to the cache kmalloc-128 of size 128
> [  118.004873] The buggy address is located 0 bytes to the right of
>                 allocated 120-byte region [ffff888165906000, ffff88816590=
6078)
>
> [  118.021331] The buggy address belongs to the physical page:
> [  118.027566] page: refcount:1 mapcount:0 mapping:0000000000000000 index=
:0x0 pfn:0x165906
> [  118.036221] head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped=
:0 pincount:0
> [  118.044530] ksm flags: 0x17ffffc0000040(head|node=3D0|zone=3D2|lastcpu=
pid=3D0x1fffff)
> [  118.052494] page_type: f5(slab)
> [  118.056314] raw: 0017ffffc0000040 ffff888100042a00 ffffea00202bd080 00=
00000000000003
> [  118.064708] raw: 0000000000000000 0000000080200020 00000001f5000000 00=
00000000000000
> [  118.073102] head: 0017ffffc0000040 ffff888100042a00 ffffea00202bd080 0=
000000000000003
> [  118.081581] head: 0000000000000000 0000000080200020 00000001f5000000 0=
000000000000000
> [  118.090061] head: 0017ffffc0000001 ffffea0005964181 ffffffffffffffff 0=
000000000000000
> [  118.098541] head: 0000000000000002 0000000000000000 00000000ffffffff 0=
000000000000000
> [  118.107021] page dumped because: kasan: bad access detected
>
> [  118.115431] Memory state around the buggy address:
> [  118.120904]  ffff888165905f00: fa fb fb fb fb fb fb fb fb fb fb fb fb =
fb fb fb
> [  118.128782]  ffff888165905f80: fb fb fb fb fb fb fb fc fc fc fc fc fc =
fc fc fc
> [  118.136658] >ffff888165906000: 00 00 00 00 00 00 00 00 00 00 00 00 00 =
00 00 fc
> [  118.144535]                                                           =
      ^
> [  118.152323]  ffff888165906080: fc fc fc fc fc fc fc fc fc fc fc fc fc =
fc fc fc
> [  118.160211]  ffff888165906100: 00 00 00 00 00 00 00 00 00 00 00 00 00 =
00 fc fc
> [  118.168100] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [  118.176059]     # kmalloc_track_caller_oob_right: EXPECTATION FAILED a=
t mm/kasan/kasan_test_c.c:243
>                    KASAN failure expected in "ptr[size] =3D 'y'", but non=
e occurred
> [  118.176103] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [  118.201544] BUG: KFENCE: memory corruption in kmalloc_track_caller_oob=
_right+0x27b/0x530 [kasan_test]
>
> [  118.213582] Corrupted memory at 0x00000000e59a4b3f [ ! . . . . . . . .=
 . . . . . . . ] (in kfence-#20):
> [  118.223645]  kmalloc_track_caller_oob_right+0x27b/0x530 [kasan_test]
> [  118.230667]  kunit_try_run_case+0x173/0x440
> [  118.235525]  kunit_generic_run_threadfn_adapter+0x79/0xe0
> [  118.241590]  kthread+0x2d4/0x3c0
> [  118.245497]  ret_from_fork+0x2d/0x70
> [  118.249748]  ret_from_fork_asm+0x1a/0x30
>
> [  118.256520] kfence-#20: 0x0000000036299d7e-0x000000000c1813d3, size=3D=
120, cache=3Dkmalloc-128
>
> [  118.267597] allocated by task 3613 on cpu 7 at 118.176015s (0.091581s =
ago):
> [  118.275220]  kmalloc_track_caller_oob_right+0x190/0x530 [kasan_test]
> [  118.282241]  kunit_try_run_case+0x173/0x440
> [  118.287100]  kunit_generic_run_threadfn_adapter+0x79/0xe0
> [  118.293166]  kthread+0x2d4/0x3c0
> [  118.297071]  ret_from_fork+0x2d/0x70
> [  118.301322]  ret_from_fork_asm+0x1a/0x30
>
> [  118.308107] freed by task 3613 on cpu 7 at 118.176094s (0.132012s ago)=
:
> [  118.315381]  kmalloc_track_caller_oob_right+0x27b/0x530 [kasan_test]
> [  118.322403]  kunit_try_run_case+0x173/0x440
> [  118.327260]  kunit_generic_run_threadfn_adapter+0x79/0xe0
> [  118.333327]  kthread+0x2d4/0x3c0
> [  118.337233]  ret_from_fork+0x2d/0x70
> [  118.341482]  ret_from_fork_asm+0x1a/0x30
>
> [  118.348258] CPU: 7 UID: 0 PID: 3613 Comm: kunit_try_catch Tainted: G  =
  B   W        N 6.12.0-rc6-00221-g3738290bfc99 #1
> [  118.359770] Tainted: [B]=3DBAD_PAGE, [W]=3DWARN, [N]=3DTEST
> [  118.365490] Hardware name: Dell Inc. OptiPlex 7050/062KRH, BIOS 1.2.0 =
12/22/2016
> [  118.373542] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [  118.381677]     not ok 4 kmalloc_track_caller_oob_right

+Marco and Alexander

Looks like KFENCE hijacked the allocation and reported the OOB instead
of KASAN. There's a KASAN issue filed for this problem [1], but no
solution implemented in the kernel so far.

Perhaps, it makes sense to disable KFENCE when running the KASAN test
suite on kernel test robot for now?

Thank you!

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D212479

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfkMuk8dtk%2B5_7DK_h0Pxv_JNgJDL3D-8pBXOByzVOtzQ%40mail.gmail.com.
