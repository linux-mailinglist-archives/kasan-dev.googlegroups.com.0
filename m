Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSPYZPEAMGQEXBX6B2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 47EC8C4C86E
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:05:15 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-4330bc0373bsf34534415ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:05:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762851913; cv=pass;
        d=google.com; s=arc-20240605;
        b=GOUOp3vmnuheo3cppl2RrGQr+tL5YMll0y1SbeW6rYHV3tGDBecyjjnEAcmpn7CDU+
         7mbY1EFfBkcLpC2wnIol1G5DUE/DkwBzvlDFios6jhIMAcKedDkZ+iSEQTyD1UnMz3KB
         Wsr5uYuGVD+9RS4tHNsSBnq8KjvsKcZcF/keBv5qsW9hzMTz5LPWHiDGvcc8l334uZBF
         X/fQX6eY9W8F56/KKovgH0XYD4QbDJD2XLgPDNW3gvBocDak5UrNGvQGBiaiL/iaa1vS
         1/x4Eaoes1dStWVdNKSRpcLA6tN7g9QCJUur4R62CrmFVHC9ql2FtnVn2XgN/U3L6vNw
         f1wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UfSFlL5te1/vYdHsnXmNVkGPM1YJayA7PKkXUdSUHnA=;
        fh=zL2JcAU+Bl7q7SpN4rv3riz2snmCyc3QCYV3lnOyVbw=;
        b=YCZXR4vdCT5x/rHNa0Tqb28pFAlK+Vf9iOPefmkxCaD44ZjtRg1c8mo0LK3sGDIIyW
         5LY27VxFEXJKSKw0IjXxbVzdoAfefsnfQHl+UyS/Fa/X/bwheeDz+Sq4HVjgyt5spIPR
         Ia9dH5TboZZrXzMI5HfXPMqGoNxg06fTDAjy+R7viuS7eGpe+H093up+prVwMuXW4V5Y
         7INrUtd4G6eU4vcVEJFVA74Bp3wQIoTkW4n4k6bH1cazqGM+YMrdy7VafSisB/cgcVps
         f9Ay/04MD/JqAnFfqPyxBmkaMz9wvsMrAAcgfVrmUkm4x2T+9iRqUX4SRbRpHJUwBJuG
         KGSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=F1WaQ5rA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762851913; x=1763456713; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UfSFlL5te1/vYdHsnXmNVkGPM1YJayA7PKkXUdSUHnA=;
        b=BLeh/sO/V6Oo5AGF1cOqZEk4YWO4HAewmLd4m2RqaD02m0rYAychudipCLZaaOx9pw
         hQ6v4Fqn77EhyAIZFIGzdY94DX6HYoRT5LrLeIT/j2Z+mNAy5cGw3NzNVTxqtqUEEEbp
         6JRN2O0t8JyYooCiH7V/DhHOiTsD2sj7m9khHEhTMLIUcRaR486Dn6WSsOsxtB2EEuWq
         LNnGLOYujGcIeXlj5t/6WITeN9/0HK1fi5C2VZfhLzPKAEDDd60UW75kJEzSqvwU8hvt
         Q5rYrr43O0ti7Lpay8WLk5kDshsF4zg6mX2Ojxf5vZhl6ZfMs1LOPNvZJ3oaaSU2xjFR
         qYTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762851913; x=1763456713;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=UfSFlL5te1/vYdHsnXmNVkGPM1YJayA7PKkXUdSUHnA=;
        b=FJXWtzUpJs/SB5VBUhm78YOlKIfupG0arzMWQMrraA2aAcoK2a851DMDmi9OAwkGPY
         +pJvPaps+w5aRCT7m4NoOwO2jsT5S36x6M36sq9Yu3EjQuRZ7q5TRcRcjp9/LyiYzyin
         M+2UdEVlz3sQpyeOBQf0kuMo57bDahvioMrnQ8wQZDuroCMLT87iX4Y/auoa9CAoZjbV
         YqiedcHGe/XYHlvXiskChGKg0L0+hEiI9/wXndQCGaqBitZUfdm72EUrEksdIbFICJBo
         9fxnelD/EsA4M/LuJHM4Do3BNLSYEUiIPIT/BySyrXND2Kmy/iN06YJff0ecCyP2FTEt
         i6kw==
X-Forwarded-Encrypted: i=2; AJvYcCVsHdg/1c7ENhMF/JxsCNfWpw0NWGwnZLTm7pV+1PXFIkcTKn3vc5WMX9JxJaoldyINAPB0rA==@lfdr.de
X-Gm-Message-State: AOJu0Yz/8n9WonjbbJmxkhVxo5sOVjQIjWeZ5Zg/CnNHnmfPH0nUPTap
	4SVneCP9PdKki0GXI3tBfbyUeGuHGIkZBON6x99UWETFO17txqZNqhwE
X-Google-Smtp-Source: AGHT+IFKKMLQnX1d1FuB8H3soPthc0Qaf/g0IK0APsvkDKcxZX40GHcEpki//jgIjAruFqVu7NL+YQ==
X-Received: by 2002:a05:6e02:1fc7:b0:433:74cb:e13 with SMTP id e9e14a558f8ab-43374cb13d4mr136248555ab.32.1762851913411;
        Tue, 11 Nov 2025 01:05:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a22RCivb3YP/Y+f+L6TPXdLylF93pG7nTlhk7xDAmMcA=="
Received: by 2002:a05:6e02:4412:b0:433:2dd3:38e0 with SMTP id
 e9e14a558f8ab-4337ab3d10bls12412545ab.2.-pod-prod-09-us; Tue, 11 Nov 2025
 01:05:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVe4kNS/OU5cyAtJrvBqgDYeahwqKNDDL6GSyqzRKdmpKRT6BBtLEuv8B6TdNZ+tkD+FmnoxwVbvCM=@googlegroups.com
X-Received: by 2002:a05:6e02:1fc7:b0:433:74cb:e13 with SMTP id e9e14a558f8ab-43374cb13d4mr136247855ab.32.1762851912571;
        Tue, 11 Nov 2025 01:05:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762851912; cv=none;
        d=google.com; s=arc-20240605;
        b=JmlqEPd2cwFBEnUbBD2GVSuxlnnqMgkhwVKrO9w1b3P/J2eAmoCdmMW2HeHMePVeCp
         aOPnQkLZ9Y2wxu0NViIMG6aRAFW0TpkpWmB3z0E5C6xjVa/s7DnXtw7nUwRJs4ignQ+H
         wsNiwwj1cv7mqdEvOw6+4new2YZAM7TZ5Cdk3HkeiDTTF7n69ojat2aVq7oB0e59yZnz
         yvB+LFbUE3p9f33PjL7Knl5WJ0zH7cwLfNdxQs9fAYwQq5Vzpe3HDnggeUxnomHop1Yi
         Grr04xSrrKVAt9+zN1+FJFe3BLmwJA99jAuO79j2zMODfY+yq9zAtP2+6+z+ScKxk3qY
         Wl0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RciqffmsGUnB8tK3sBcxSnH1zQElvWzvEdnZAAXNZdg=;
        fh=75M1U8lUyWeYt0ngxeiQyiKFwQqHBfem6wfK81xds0I=;
        b=D3EQCmdYElJf6ZRRoJaHuRCdXVJZJNlJqjENgiP+Jd8OyChssrIAp7TR8YxJpVXmBr
         4RxFsYg/L70yZ45Pksj+u/k5ZWIXvDc0SJcO4Xa/zK9LsqfeQku/l9A7WfrUhLmzCqcw
         oW4BfVDyp258XTXLVgoyV7Gu6g5SXaXuFLDd3gnPr07JghedLnlEvyz0kES8g/5hB34i
         pxrKF9eBi0WU5a+F31C958q5IKJbMykst90rwLLnhwU+9s2N2HHXZpuOeH4EBMeFXDmp
         7V2LPnii7/ZuxewOZWFUcdK+F8syv+KVHQx+v1caseYU8gMqeIh9YrLJQfBWRUmz9ZAo
         ZDqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=F1WaQ5rA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4338ac85040si2288085ab.5.2025.11.11.01.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:05:12 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-88043139c35so40260256d6.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:05:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXuN4FjB42pGshwC3tk9KCqGopN97dWBPUq8WtMx4VR74ZQ/o+Xo1s6sILAioq2eYZIT3Ao6rQ2bwo=@googlegroups.com
X-Gm-Gg: ASbGncvDBTNxDcyDpMkK3pFZGLeihtajgI0jTWmDQMlidfshTqktwmdTsQAyyfmQbpx
	LwupJgU7nYKMgIvFEjMHYweIEtDR26GhlhhQQ6x7B9YoUC1pipdZfxTnfeL335DDs1cMH5X/kyF
	Gqov9cy8IAYmrxqhXGuzoqRuM9PUZgHcPHl/R4IDDmm1eOR/VyVN+bc15iZ02USIgZulvV2LVT9
	jnhI/SUhy++AjhM6dsQ1UU7uDu6J0tmGO3GcLMJLTicmSgUJHDdmNvCeCXSRvWjfxSN3tV0si1M
	LeaMLgPoH56cfPeZ4gE2b5KTJA==
X-Received: by 2002:a05:6214:d4c:b0:880:56f6:92ae with SMTP id
 6a1803df08f44-882386d7384mr151892296d6.57.1762851911409; Tue, 11 Nov 2025
 01:05:11 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <96559d5a8e897f97879259bad3117db617e21377.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <96559d5a8e897f97879259bad3117db617e21377.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:04:34 +0100
X-Gm-Features: AWmQ_bnTIARw6amUs-gvSQivLCgG0XY32k4ioUAxykbqmf67HMroMwsIF2IdVwY
Message-ID: <CAG_fn=X5Dr_Dc1pcnAW19zgo7tW8mUSkpDj-v5eaG-awy4S53Q@mail.gmail.com>
Subject: Re: [PATCH v6 13/18] x86/mm: LAM initialization
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=F1WaQ5rA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Oct 29, 2025 at 9:08=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> To make use of KASAN's tag based mode on x86, Linear Address Masking
> (LAM) needs to be enabled. To do that the 28th bit in CR4 has to be set.
>
> Set the bit in early memory initialization.
>
> When launching secondary CPUs the LAM bit gets lost. To avoid this add
> it in a mask in head_64.S. The bitmask permits some bits of CR4 to pass
> from the primary CPU to the secondary CPUs without being cleared.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DX5Dr_Dc1pcnAW19zgo7tW8mUSkpDj-v5eaG-awy4S53Q%40mail.gmail.com.
