Return-Path: <kasan-dev+bncBDW2JDUY5AORBNWT3G6QMGQENO3LQQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C436A3CD96
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 00:31:04 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43947a0919asf5098965e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2025 15:31:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740007863; cv=pass;
        d=google.com; s=arc-20240605;
        b=A+eUSaoLzF3S+vpZ0gk0XEDUDR963IarafYo4HpALO1VWnV8fEH5gYNxgu03jTVn1W
         6Rx0T/Jk4mKe4wQBeHfzkLyM6VHTPU92rdRaTnOCkrU35IKer7c4Y7gn5VzEGUuGyvZr
         7m6YtUVcTz+qouX8mysRWrdh75LkrACA8f0f0jUieYJgxLm83sbMmo5peNrb4K01ZQWK
         YaktR0V6m/sNi+XwduiXZuKDRORPh5b+t4/lN/KNSteyI5xbf9wh0h1h8UtPwEHElTH/
         WXNw+4ifuJEIubXclRgHSSNbWq7kP2wH9bypVMVy7/SiliqOJ7wmwGdXM//orCBxR8fE
         YeGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=fSs+POht8M/p23faXoPCwnu+LurifSsget6qm9xSOSU=;
        fh=aQjWFwB3GnTX3HhldpPyX0H/om+Swx35qXY5hVHskwI=;
        b=ec5iEHBBYhVNz+1ZPfUWp3hEsBxeMDlswpSRAJRKJkBnomOcfTFs93xp3rlZRfu7wP
         7I7C3ymMpimSiMS0cisJkwqqM3YbgF5BMO+4iQu0KIOi3vrVjDTkVziQIHyj4+OartBX
         UXspn0+wWQHsgJsVzxvO1oz6wFk6XIXED6fLyxyAnA/SBA7Uz+zfiw2gG7YQDHkFERiv
         hzxYkqEtADjIS1jzjyoMeN1aicixWKu4dRS3+KThVPwlG/RsEo+2/Cx9Rsp/VRxneBMO
         WtNPBGqVUdOimw5Mf/ImXjhK51c7g7qDy2Xlo0163cPnZWoOcgGePJoPrLJm0bVr0M0v
         OS/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=K5QEaFoA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740007863; x=1740612663; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fSs+POht8M/p23faXoPCwnu+LurifSsget6qm9xSOSU=;
        b=byYpws+Dif0h/alqBIttpvz7cOtKrQNnRUmr/96ycZcB5RyEmZPfmrSHJDZSeZnajR
         VnBd48Z1v+/ED+gG58um9EQ1xFhwUxHHRD0z7Uyftyns6bGUPeL2FyQ8NgqfWP5bEjfY
         dsf8PimY25hoiJgL95HVIbPdUlF2bV+aTrxqHrCZan36OhYguV8w76hNV4MPPNg5J8Aj
         W+enjg2O6d89rAMEh1ue+C4yTBz0IPP1Pv8NJM3Pso6+HgLG0qrTTAXE0r0+sActO9JI
         Eqm/MM40zrkfUVTwg9uI9OnWYtgMj+2OD7cF7GmNckLq2xGWcVkBOVkt7T48kRlr1nOb
         aGsQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740007863; x=1740612663; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fSs+POht8M/p23faXoPCwnu+LurifSsget6qm9xSOSU=;
        b=mtEgFIiD4vpeHN1uxjDbqmKEel5jiqFmZQs40ZqJ5PgWmlGJhquHZHNuFqTwB9HUV4
         WiZP4953ukxwmg1Q6pgOZcl/CTrUsSOU8g50mtcnYxzt4D/em3pAHdP08bf90eEJqWXs
         FfJAUSjPBBJXAWuIt0lmJcwtv2YsPPi1FqznlBmMqJ9JfqBkAsW29Gx6xm8DKRQ/9Ly/
         FGfVH9CNxwPUDDUsgqTh4W2iPeU3Vac1xI9cXZtMqUfVIpAKkfnLlDvhDs8nZlzRvRYK
         AgBpLfGqI9KxB5sYibuE3zDS6z20u5PzVU3LNLYNeLrWcNbHV/3eIgEkePLNergzxnM0
         txUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740007863; x=1740612663;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fSs+POht8M/p23faXoPCwnu+LurifSsget6qm9xSOSU=;
        b=J1x0QK+ldp3x758bK1KuzYKJW+Gi8pVIAiN1Zb1NIMTFXWsMAwGRg9NDGLGysMsMC7
         DMGiwb4oNF4Cngo6MEUO76cXktkywMyitxc5OLxyhkv2jQr+nsKEOAcdep/fJpgzWGnj
         NTcYex6Pc5eSTn7JwqQ1BDdVq1DYyfb4+q33SPNm9b2YDM0rhGSvYePZlGIHMI7mqmdY
         2dxnB/+Zvjm+XLmAiUbSyEkQBfVfT2v15De0ZGVCHfAgnPprk7I7Aq5VAv+50uclCKfg
         WQrItPTd0rGbJgIzv0MpBvdUcDR5W8S2iFb6Qd0oHQC0PB+ZHrFYOpDIhPF0tv1gZjYw
         4lLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhpwRPS8SV/TbhCPAfCBC+NusKhin89Zc0WxyBFfBodZqYDe+EIP4L9kPBJsv6SIiIIHwFLw==@lfdr.de
X-Gm-Message-State: AOJu0Yy4KIuHXdySwpWd4lQn9+nG2XTiY1eK5IbTO8LlBiSnD7oHKqKG
	eHu7u8xudtqKajoS4B8FLu4aoNzEMm1InOQ8RMvS59YeruI6B5Nv
X-Google-Smtp-Source: AGHT+IFNnETsey7SYvR0p5edb6/jptRr65YMc4ssEcnUoSCIViSZysnEFcrXbKaIzZLsqn6FfEW17Q==
X-Received: by 2002:a05:600d:8:b0:439:86c4:a8ec with SMTP id 5b1f17b1804b1-43986c4ac03mr142819475e9.15.1740007863102;
        Wed, 19 Feb 2025 15:31:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFi0vIthUcvBVT7msk54aD9sTD65rq5kZWDWX8Z5G+Giw==
Received: by 2002:a5d:6da1:0:b0:38f:22fc:ecb6 with SMTP id ffacd0b85a97d-38f61490efels306295f8f.2.-pod-prod-05-eu;
 Wed, 19 Feb 2025 15:31:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU7eXT1SIKT9LLvvIWbSiX7DoMpsxUDlenwDO3C8W1yZrH3IB5HrbKf4sPoLLToFY8dv0ySIN8ip68=@googlegroups.com
X-Received: by 2002:a05:600c:3151:b0:439:94f8:fc79 with SMTP id 5b1f17b1804b1-43994f8ff8amr106606935e9.0.1740007860669;
        Wed, 19 Feb 2025 15:31:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740007860; cv=none;
        d=google.com; s=arc-20240605;
        b=bmiSqRZC4jn2e9YX8BJrUIhYxtJXm4XA9w7PodF4RBG+VD+wIDIXyaM1kev1c+LgfC
         11A1Q9r5RSS9baWEjH86kM1uDLT3ZWw0YYi0S5JhI1vyFaB5CP7hPEfAgzwPdVGsY7UA
         nuCrbFXEnJ4Ng9j4nPqzdLZrn3QcUvuXSpd9iKJevAOxRNkIcgKQ92ks+EaYP148X4Tq
         endaxor5M+OXSP5o/tKMFCgtnlggPONhZSdd0pBH80I/xtF9IZwi9VY0Z/VWxcnph7ID
         bLAQlPru9KU/HegnJbtQmyADF1prwxcXEY2kMCQQXANNQBNckwBwA6KhAV3oaNfELFZj
         MbeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4dUybulOhS0kE/3bK++ET9eEzpvtsmycFrLhnO/LKN0=;
        fh=aKquG9WMql3GCK77lv/7wxm+uPZghgIi69LVxhmRJ64=;
        b=lr/75MQ14FtOeMFn3FsG72iMkjoFskw+6bwshheKmJbsa8pwijwIDJTlbcn6yn8kjA
         9IiZrpE3+XU9K4bs14jwLiFaAfcRfbjFiM5JAwdf4SGAig70szACR5hwBr0cu0HY6vbM
         pV/Ctg46j9ZUOgvS9rwYI1spWIurBCU9a9SwkSBPSXn4Hk294qJsjpCIdlCtogbc3eCl
         dp3Q1+75FfxYEI6+FbJ5cGUoI33Eu0HZlhy7FWv/Z4ZnZpeMAB/wru7mHzeHmzFi+geQ
         FDzjnH4/uBatXuQVY7d7aE2ZAInOa6rjhXdmHwCZ+j6q6bN2wfP+IJbKnTUf7TBZ4FU6
         Nqtg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=K5QEaFoA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4399bea9edesi2070705e9.0.2025.02.19.15.31.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Feb 2025 15:31:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-439a4dec9d5so551135e9.0
        for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2025 15:31:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUtM1yHgsmRma2ktMUHOdS2V8IlNwyKJVenglw11i3Ujafz+9S4JMxfgUYxcvfBlYFvjf+5gEKI1OA=@googlegroups.com
X-Gm-Gg: ASbGncu3wvSAymzqiATa9mI7CT9AyTTKUT2LsGn+EE6bRyJBwQeTjt6RRa7mcmYwwP6
	BT3v47p9Fn5QImFSUX+XC4xE5GiYfL9ZQB+QRYH+dDVbMQ5BltUJXP2VM7+TsSMQfOgTa9CKLR7
	0=
X-Received: by 2002:a05:600c:46ce:b0:439:a255:b2ed with SMTP id
 5b1f17b1804b1-439a255b574mr11307125e9.9.1740007860050; Wed, 19 Feb 2025
 15:31:00 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com> <7492f65cd21a898e2f2608fb51642b7b0c05ef21.1739866028.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <7492f65cd21a898e2f2608fb51642b7b0c05ef21.1739866028.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Feb 2025 00:30:48 +0100
X-Gm-Features: AWEUYZl1gRQjDF8bP12LoQKOk6SUSp8U6yzsjJnNm_UbyNhEUb3N5bt4_wbtQpk
Message-ID: <CA+fCnZdidM3Sj_ftw6pmtzw-tjy0LLD+2aqtzSewQTOUXMs2hw@mail.gmail.com>
Subject: Re: [PATCH v2 12/14] x86: Minimal SLAB alignment
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=K5QEaFoA;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332
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

On Tue, Feb 18, 2025 at 9:20=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> Adjust x86 minimal SLAB alignment to match KASAN granularity size. In
> tag-based mode the size changes to 16 bytes so the value needs to be 4.

This 4 should be 16.

>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  arch/x86/include/asm/kasan.h | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index 8829337a75fa..a75f0748a4b6 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -36,6 +36,8 @@
>
>  #ifdef CONFIG_KASAN_SW_TAGS
>
> +#define ARCH_SLAB_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)

I believe ARCH_SLAB_MINALIGN needs to be defined in
include/asm/cache.h: at least other architectures have it there.


> +
>  #define __tag_shifted(tag)             FIELD_PREP(GENMASK_ULL(60, 57), t=
ag)
>  #define __tag_reset(addr)              (sign_extend64((u64)(addr), 56))
>  #define __tag_get(addr)                        ((u8)FIELD_GET(GENMASK_UL=
L(60, 57), (u64)addr))
> --
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdidM3Sj_ftw6pmtzw-tjy0LLD%2B2aqtzSewQTOUXMs2hw%40mail.gmail.com.
