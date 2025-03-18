Return-Path: <kasan-dev+bncBDW2JDUY5AORBLNE427AMGQE6SLULZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 08C75A677EA
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 16:33:03 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-43cf327e9a2sf27937465e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 08:33:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742311982; cv=pass;
        d=google.com; s=arc-20240605;
        b=akW0jxaykbRKLXtKhvYDM0oOcFhcdPnzbvmWkOptMcHY9nf64qeY5SwWwvMI61raf8
         l3o6iCaqJaH1Y3P9HuS//wc+Eax3AjzV7fhvNGvL8VUdJnG6/BAPNardz/JStRrF1DFs
         GR4zZbxCIKMAYz9ceGqHoEmk3+rQIhst5dtjZ1jWgdoKb+AoLfmHACAKMBwC7vkk+Ejl
         JBxXCUisHQU7vw+bYP81wXfvF/qj2GW1A2R0H82a23rH6t/nQ3veRKQKHAeshJ/WluMr
         K1ruicoezniz1qFa+QoFdL3Na1X7jgKV6ExIraPFbOuhvV/E4Ats//l+gxAwQdBkyyMK
         LHbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CmY+FFScqMnsP8d9LKjaQNxoG7wcQxc+8mtMYHT598g=;
        fh=NTH782nGD5UER41ZuhVsf14ZPIEXkfPMdRawol/s2h4=;
        b=iLZnH6MejjMAzxTkwxbIoCn3fHpT0uaV1GJYnXZygDjdqimsnU0NO6SliW2GMDvZDz
         1O4DlQlqEMOsMAB8rD9rJtDxOgu3OmSPbaitConkcWsxoEDtTkr7yrYGVPzdYFkA+y7z
         9eKLHEyX5HBCT7O4R3yYPcyBmg4SAl1kTXKUcw1oETV7D97+FVeNSj5Xin0VP+ds0EMO
         5B8xRzJ/BbzyQYxztbfCEYnpLRpsB54GL/kxn/4TINiXPrdm1CUd96Db90OhnOQu4K3E
         sdA8o4WVAoKKvzgRZ83ES6IzOpfj1LQuRfIM/+NOhERZQ5Seh8SLADith2znNE1egM1l
         DhrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eQecTwm7;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742311982; x=1742916782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CmY+FFScqMnsP8d9LKjaQNxoG7wcQxc+8mtMYHT598g=;
        b=qpBw6EjGEbTo7JHHFnZW5ryMiSHKtrl8tnYpb8vLy++h6UQVHN8NqRWnJ+gfF+p+H5
         huZUc4MYcjp2tJo20P8619lXFg/efHgOjybT5RRbQ/56x/S7ZIT4MxH5EYtjXAkCXcr3
         VSzCIGCYvEWvjUvisobCzr90sGf755+MWDBusu7OZMHujuRj9fDGUoEUBFsb6ufsKhmJ
         N118vDQ/wrFB9HUW+mfVEFcjsA3q0Wj5JsRxi0IGncLFUwAa+8icj/r5Cso9u2sIdtan
         H282edKYCBlCzI5gLRRZBAnvkvZCPmUBWWl3V2X3vfQL4Hfhr03olXePtYtvasM4KWG3
         CfJg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742311982; x=1742916782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CmY+FFScqMnsP8d9LKjaQNxoG7wcQxc+8mtMYHT598g=;
        b=PjclEsgAJo53OM2JNbnfrVnlPLTRzJCr0Itj+p2OPNHYJno8NsCqulwEdoG2p+iPrt
         FVyhLgrxKqQ1EUdvNTJ6H1xljVbacZ4nx2cU5WweBW31jFO4fFHFHpPpUMen2cepknpZ
         vvws6FhhysbJKNAabgcjxppwQXeQxTQDhd3DbEzPGyB5aTIIKd5A+52d9xDQ922EjYOV
         hKaO4TI+2u1EzcPa5dv959MJi+Sjn0ckjMP9u0gEWyvfFdSbDk6vdjs82V28QXKVDz8K
         3rHmzlG7Fg4hh2SU/6K3sEzh/1CuXC5jk05QBkZWr7a5bG1mI4c7kDJpoDs0pu2Ad87g
         KvZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742311982; x=1742916782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CmY+FFScqMnsP8d9LKjaQNxoG7wcQxc+8mtMYHT598g=;
        b=IplS7gA66ZTIbp10Ya+FOiJ97AVtPdWxzRx8+a98Zy/bnv72Oq1TjrRf1cfVeSeJ/J
         PYE0rh3wje/Z+EzfPU7JOWVzEfHXA4QeiNSJYcrE6NsDqIc8UBECoVm9zneOiRQ6u52w
         lFlL/SR9z4kSklfw1k1IPgof9ys17HbtX9ojvEHsar18KgndelQwi28g9t9szCNJG+J+
         MhClxUzr+G0dN0rl7TPQ/E4Kf24CxvvcbyG+EXFsAR3IWx36MOSM+Fgz2KS423HG42Cz
         ndsQUub50hggwO7vDLxK8tyKvYtI/FijpH3rVwc4LAeM4ttSnzF7zLAtyJvNO1tLd5dP
         83xQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXzgOgJw8+ux9a6OcgE2iogAmRkMrUIEufS+rUU+cM+F9lX6yBAk73zjL/v7QWFmS6gjkMVEg==@lfdr.de
X-Gm-Message-State: AOJu0YzUVreRpoCXIaESi4ZhMYTW2CCm556+JZRqu/DEe04J9NKrt7qx
	MvmCeVR6BiSMX6lQXNb0UNRGX1dMcuiC0HWMod5CpILBU4fd4Si1
X-Google-Smtp-Source: AGHT+IFvmUjV+XxUGchFPTflDy3tagL+Ic1SogE/fUNpjG7t46oU8yc7FpCein0Y75/iLGMQWu9Bqw==
X-Received: by 2002:a05:600c:1e0a:b0:43d:1824:aadc with SMTP id 5b1f17b1804b1-43d3ba2109amr27778865e9.29.1742311981675;
        Tue, 18 Mar 2025 08:33:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL+G7zBhr6c3pTixYun0ZiKYTBG+90F1Q49jCGmsPXliQ==
Received: by 2002:a05:600c:4ca9:b0:43c:e3ef:1646 with SMTP id
 5b1f17b1804b1-43d40beee9fls546855e9.0.-pod-prod-02-eu; Tue, 18 Mar 2025
 08:32:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4CSr5oqcGdOkIt0D13CdQ6AamYqBLTOaE9m36jg4DaaPJ5IxT9u15Q0f05bcjf2HdNyDysUWckno=@googlegroups.com
X-Received: by 2002:a05:600c:5103:b0:43d:fa:1f9a with SMTP id 5b1f17b1804b1-43d3ba2971emr24276555e9.30.1742311979478;
        Tue, 18 Mar 2025 08:32:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742311979; cv=none;
        d=google.com; s=arc-20240605;
        b=duFl+/ZudZKsIkfnz716N+uOCfd/xRwquXoGPld4KLoMBFy0x/4ogSIpcOiKjrmGUz
         DlKo8mIUcrTYLMQUazV/6LrjfIKz1Jgz8X8OjN87M4ITZCmuGDLgfntVZ3auKaV/Q4pg
         AiU1u8P99kNKg5eDoEbluei1cLzT8D+G96Ja+sgm04Q1hW5TVSYzmePTYZou3T+v2voA
         8cyhU6s2IGGtsYwYRqO5xRljWJdkerW8YdphBp2hwhLyolAAntieINmwmkjaAe/4E86/
         3vQUcf1OMOiUWAsjKVzHRzsr0qkzvecLb3xHzn05Ivsjvk7UTBs2Q0VFPq91mQxTfZNh
         R4+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=68y8GkdAQLX6Usa7pa9vQcmtnJMUrq8yth4Y3tc6GKw=;
        fh=M5yJobTqbqMqOWsERfyhByemXX/7WK/XDt0y2vwr0K8=;
        b=GRHr0oXma/YKltrZEp2tk0vRKsCA3/1M+/tgRtj2iuUzkHHeqNn4nEnHg7gE4I+csI
         9mIO1IerGF7iQOagXxxxJwKo8dkGD3TCjZCxMEZq4Z8IJAo7L+RbNedIWRUJfF6wGdtK
         IjumuAP6IejLlTfT8KF1p7+kqQiEDtjiJisqXeg2b3L5fG83W1v1+ugZT0kLBRbFZJfJ
         Ahop4evRRhe8G+KWiAPR4f6IxqvJUgtRJunVQ/i5lenM5xriEqt7Ey+xHTgY+TUL6Put
         WqARGwuYGw9vDvUqtXDYyn/XCs8hmQ52TbA13TJTwVykGP+vZG2ZWTDoG7LATMV58B4q
         xKig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eQecTwm7;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d3b9d3a87si932535e9.1.2025.03.18.08.32.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Mar 2025 08:32:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-3965c995151so3851677f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 18 Mar 2025 08:32:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVBlyGNuwpnCwJbGbSy0KWz1YC7ocnMdTr3DEUaYwL6lcqpsqyfENCTFejyEq6E/q0bm3ufO+YWxGw=@googlegroups.com
X-Gm-Gg: ASbGncvJFdajxuRr5n6uGyAabufKFwFkDuXu5YuyDk/LYRATYfi0e5eAUn/I972attO
	288W3rZHFQl7ON8hrAeiYZjawCTx0kiJ71M2FnfbUOvhr204YjXjIxj9+QXIipIVQWwjs7BUL1l
	QdgozwsXKFiJpswTyKSYzBPWvdSV8=
X-Received: by 2002:a05:6000:1447:b0:391:3207:2e75 with SMTP id
 ffacd0b85a97d-3996b45f0d3mr4021787f8f.18.1742311978657; Tue, 18 Mar 2025
 08:32:58 -0700 (PDT)
MIME-Version: 1.0
References: <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <CA+fCnZfb_cF1gbASZsi6Th_zDwXqu4KMtRUDxbsyfnyCfyUGfQ@mail.gmail.com>
 <paotjsjnoezcdjj57dsy3ufuneezmlxbc3zk3ebfzuiq722kz2@6vhollkdhul7>
 <CA+fCnZcCCXPmeEQw0cyQt7MLchMiMvzfZj=g-95UOURT4xK9KQ@mail.gmail.com>
 <aanh34t7p34xwjc757rzzwraewni54a6xx45q26tljs4crnzbb@s2shobk74gtj>
 <CA+fCnZdj3_+XPtuq15wbdgLxRqXX+ja6vnPCOx3nfR=Z6Q3ChA@mail.gmail.com> <b2bioloa3qsueqiyjadi5zsvi63v6zh3vwzji4ed4dmsxkaudb@hrxzs4vh7wjf>
In-Reply-To: <b2bioloa3qsueqiyjadi5zsvi63v6zh3vwzji4ed4dmsxkaudb@hrxzs4vh7wjf>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 18 Mar 2025 16:32:46 +0100
X-Gm-Features: AQ5f1JrJPlldmh-W4saMlKXW0Ok9D48DqwKxa7GZ64X93-bATE_KAdVxzbhhhSM
Message-ID: <CA+fCnZd2xPEwMGP7QRSyqHAJEbs_TY8Pg1ijG0iDFojMzphnfg@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, mark.rutland@arm.com, 
	broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, rppt@kernel.org, 
	kaleshsingh@google.com, richard.weiyang@gmail.com, luto@kernel.org, 
	glider@google.com, pankaj.gupta@amd.com, pawan.kumar.gupta@linux.intel.com, 
	kuan-ying.lee@canonical.com, tony.luck@intel.com, tj@kernel.org, 
	jgross@suse.com, dvyukov@google.com, baohua@kernel.org, 
	samuel.holland@sifive.com, dennis@kernel.org, akpm@linux-foundation.org, 
	thomas.weissschuh@linutronix.de, surenb@google.com, kbingham@kernel.org, 
	ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, xin@zytor.com, 
	rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, cl@linux.com, 
	jhubbard@nvidia.com, hpa@zytor.com, scott@os.amperecomputing.com, 
	david@redhat.com, jan.kiszka@siemens.com, vincenzo.frascino@arm.com, 
	corbet@lwn.net, maz@kernel.org, mingo@redhat.com, arnd@arndb.de, 
	ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eQecTwm7;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434
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

On Fri, Mar 14, 2025 at 4:58=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >KASAN does nothing to deliberately prevent or detect races. Even if
> >the race leads to an OOB or UAF, KASAN might not be able to detect it.
> >But sometimes it does: if poisoned shadow memory values become visible
> >to the other thread/CPU before it makes a shadow memory value check.
>
> Thanks :)
>
> I've came up with a theoretical issue for the following dense series that=
 might
> happen if there is some racing but I'll have to experiment if it actually
> happens.

As long as it doesn't lead to false positive reports or crashes in the
KASAN runtime - I think it should fine.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd2xPEwMGP7QRSyqHAJEbs_TY8Pg1ijG0iDFojMzphnfg%40mail.gmail.com.
