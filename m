Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4XWZPEAMGQEEO6NDWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D27FC4C80E
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:01:40 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-3c98354c16esf3784429fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:01:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762851699; cv=pass;
        d=google.com; s=arc-20240605;
        b=FfFZSLp4X0g6ncRN/52yjpwThgvLt+rVIs/0XErKfR4tbYo4wNDh8ji5bdqF713cou
         pmJIS7QZ5FPhkxe4yfRkLFyH5Ci1Ik1Jqh9eyV25EEpcIM3wXPCioRDbFSfRqr6wRipd
         uFEDxO7zRw486aVr+ioQYfq2T4zSrFMtykcsfWMGMLqsHtdnHpXq9O40qKZK3JeH1ASF
         eBFbimzzmYOFnSe0+wPwuKGCG7Lg/lU6bWilMexmRI47eULhDh+ktCiGUVwy0DSyXxaI
         BVgP4YIeAh1CopWf0GmBtb/A77nEElw8e/yLAMawGpyXHyrl4T00hMJrbqf5BgbaQmAp
         v0FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Fd9vo38Fu7sWOJXaOmj/NpoLbeav0sOmYwEG3xIQIcg=;
        fh=3/yv7APTtbRILzhpr2jlVbtJSBAx1DMjXEYKkUQbQBU=;
        b=XbJ9WCOcZBGVWJJNHEfBguQa3K4YizCWut30OoDjrufGMFBsi2ZBn6pavKui/Gh7c7
         CnRS9ZwA8PDgEmNq6+cjS0GqTcEtgVQWtYw9MVQInhtB9wD9uXp/huISJWuuErsrwX9C
         5+xtD9+VoRxHN4Lhy2g2zddSYf5EPYQ44KLfRLXeux5utz3gEMSWRAwCb7fF4QKuz3qq
         dbSeJJEXQoCvye7Ny0sNkCYNeSvtRxRi1pS1RoPw2shDtT6a83Zjxz06X/peBuIbcyGf
         7yKP7xF9dapggkDycWqg6K7PwgzZR/IZWt8AEpMRkWjZVWp0hqaQwoSAEWiOWYyS6YU0
         e/Sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SyrAYaC+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762851699; x=1763456499; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fd9vo38Fu7sWOJXaOmj/NpoLbeav0sOmYwEG3xIQIcg=;
        b=XlA3/6Q+X+wDhtD3yE0pCVEru7MYD+vsPnlhhOarvYA1AEtYhKFq04Q/XeCIFct6s1
         mBCQlFtJXCFBKg2VJbIc3CEfQbyfcbqi8xPlg5FebVmBG95rw4zHnHmoHKAaQzcurA/x
         fYKkazfWATVFBD7H+wSfdapQwKCxHiqmn6GgNQFGc7J223fWuJaSSceLXXn3OtOM+3mf
         9CWKXMy5ThhHoYXzELNhiz17EV0UHLD8QqP+3zgpOx8OW8fmJyN5K1HOBtMcUnoyh+b6
         rBJPLks9YI6MQcW2vlJ8KnE7O/DPhBRpls2dtm5To2JoeEtLRCoR0YOt46LblwIRZyB5
         ha8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762851699; x=1763456499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Fd9vo38Fu7sWOJXaOmj/NpoLbeav0sOmYwEG3xIQIcg=;
        b=IPFsY3AA5pN8AFRqTb+b/L2j+ROCkEsUTgX6QS2UcwRKk0y+tFSJENBjRU5tZwlucQ
         Az1sJmad7eqIbz8XK60K6hBeh/1FPi0Qgk5GnI71ZlKP7WgL5o+9z/CMixLaiYx3SWXR
         cgehTHs+TuHCC73KkDklO4uOSPiCyvWWFnKO5AsgD5nMHqbwAhUt09JW35VAsALVJUXM
         P49Igc16gxgVlipBcIA080DgAP0od4KcXrRSvhVr+5wDdZ9GAuAlLyhZP1XEIjxH+u4I
         i1f59ny3IwNqBaJ3lE6gxs4LfKNbAyErZCo2VpfJMFlf0WPbfZzdx/cxHoAy5PCThkk5
         j4xw==
X-Forwarded-Encrypted: i=2; AJvYcCUVh7GSGN0wUngRvp/nFkwQkH/aKmjzzdZFyZVLIsBpuvkFJOt4xpafyDkePzs1GLRFb6QxLA==@lfdr.de
X-Gm-Message-State: AOJu0YzQbl9pzuwzgsbDlu4K6rgMgw08KUssWxssQdUp4k2zxw094NVO
	bKMqepC2BEwiE5MyAA6NuNVKw3aQgXHzZ26zrtl+ccVQW192F5YjxDv8
X-Google-Smtp-Source: AGHT+IFR2pFYs19+6dFz6L5mRtREv8bwWGvfPwNwvS5itC5/Yv4E4kPNZocLkuQ2/SWlaB6SKB4spg==
X-Received: by 2002:a05:6870:8109:b0:3e0:a1fa:e883 with SMTP id 586e51a60fabf-3e7c2b98a38mr8634219fac.40.1762851698883;
        Tue, 11 Nov 2025 01:01:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aZLHxlmdluMM/5FyXJfzNTnNtpW6o9EcIwp4bDSUjt6Q=="
Received: by 2002:a05:6870:320f:b0:3dc:b022:7efa with SMTP id
 586e51a60fabf-3e2f5daabe9ls1946321fac.2.-pod-prod-06-us; Tue, 11 Nov 2025
 01:01:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXGZ5t8hGpx9vNBBg3Oj5KHUTnFXBM6rv7HZyAUCYhDt5109crTZ3ZEFCfkJ/fHFJq5xrIJ8liwnik=@googlegroups.com
X-Received: by 2002:a05:6870:1719:b0:3e7:ed56:1634 with SMTP id 586e51a60fabf-3e7ed56554dmr3579622fac.33.1762851697936;
        Tue, 11 Nov 2025 01:01:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762851697; cv=none;
        d=google.com; s=arc-20240605;
        b=HErZIaLbtl5wj8r/8+3cz72XodOURzI6ow8tNjDvYpvP15wLGLb89jAtlCGO19Cmxt
         Ue1KX9xYvr9XrC31+Zsjs2JUol2SaDrWhGTjxtHWhhs78PRvlTZZc+ytqNWDdA7LrQh5
         VrWmKIrBgkRELIwuUkshChI7DHN1HydznLp21VmwB7FlGnUqVBpEMpgEbHtSOTbIHEnI
         JhZ60mfx1JfkWoV+Y8NQ3O/X4NzaKybkuLRfeACT+ZQXn+HC/z/ocP1OGg158dTwTwsr
         ABMEz3dcUCmMdlvN3xQ9v7J3wm4ZiSYc+84Bj2aCxibX6D8Kun+a0IDCJAL5RxIf0k71
         slgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=s3GiAAjmzQ/VspCqloDpIt+ugCtvSToogOEL/VpV0Ws=;
        fh=pFqzAKPvka8kBNxIs1LkpjYeVZNt6quI6WJDxVlDOvw=;
        b=d74/D5d8BhRJ7syGvrFCLr/vJM1fVSV7PxLH6JD4JRPbgt/6RKIGt5KljZlmPk5kv1
         2/6+54Qa3H2Aa7kUGILWkMQs/lUlllh9HbMGFVFelzJuS/vaY1NxoeR6wb7qULUj9PNt
         KB84vZAhOAosR6Fd54a78j7EgGhdUUnF3Aq9KphWsP44ct0Iw8MAHTHtJMMxlsgHkhvH
         QhyhtjcN4hI7pJDFWkxV+H1k8r9CxqTTrgapVBCKPdwpBIBiC+aCmBRKvcmEmNmazxQR
         36BM8CJhjnHL+VeAIcD5/8MGAQcoXdod3rwm39wPWJWTRI2g/3B0f5Uzqty4ukUpmMzL
         75xw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SyrAYaC+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3e81a98bad2si31005fac.0.2025.11.11.01.01.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:01:37 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id af79cd13be357-8b272a4ca78so308360485a.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:01:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU0iKHGNfTMFoZjK/th0FIRkl/Ez2mnjLJTtRP0BqwInDtaecRmBeovW9LWGcbehdiFVl+wJQLwUBE=@googlegroups.com
X-Gm-Gg: ASbGncve4q/nXLQv280SHh6P9T86j9OduDK3PZTnPkxDfzqQALFNqmwVacMXLgVDJWy
	yuD7IgRKdcJfmpOCAshmP8O0c54eXLUJWxT06a8Z8IaIZmoBWN3qOWLxESkX0sAmAy3eZcbuRMb
	RXKVNzd/IOYIz6xnuUnom/gAhXZmo9fFAuNi0/3TQqwXB4RCv5ALyYbHbpD8/8wk0IUMkXuwmeJ
	uBCtPNK6ZMulneTyjpTVkLXtp9f0Pjf0EpIVSc7/fP2XTumoDS5otKkQ6szWWwx6wYqfyXBFQLi
	ycMGVOBS2odB/STkBWhDyOAh+jTihwXyKzeV
X-Received: by 2002:ad4:5f07:0:b0:880:42a7:7730 with SMTP id
 6a1803df08f44-88238731aaamr156015206d6.53.1762851696507; Tue, 11 Nov 2025
 01:01:36 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <d98f04754c3f37f153493c13966c1e02852f551d.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <d98f04754c3f37f153493c13966c1e02852f551d.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:00:59 +0100
X-Gm-Features: AWmQ_bku8cq-CFmbh2Cbwbizm47o3PsCv7pQitKRdKmveqfrADnJlpnymR3GFhA
Message-ID: <CAG_fn=WPQZ4ti3Lb+A3jSXFWLtn6291sTKJBwKBiLD2E9YbuKA@mail.gmail.com>
Subject: Re: [PATCH v6 18/18] x86/kasan: Make software tag-based kasan available
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
 header.i=@google.com header.s=20230601 header.b=SyrAYaC+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as
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

On Wed, Oct 29, 2025 at 9:11=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>

> -   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN sh=
adow memory
> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN sh=
adow memory (generic mode)
> +   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN sh=
adow memory (software tag-based mode)
>    __________________|____________|__________________|_________|_________=
___________________________________________________


> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN sh=
adow memory (generic mode)
> +   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN sh=
adow memory (software tag-based mode)
>    __________________|____________|__________________|_________|_________=
___________________________________________________

> +       default 0xeffffc0000000000 if KASAN_SW_TAGS
>         default 0xdffffc0000000000

Please elaborate in the patch description how these values were picked.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWPQZ4ti3Lb%2BA3jSXFWLtn6291sTKJBwKBiLD2E9YbuKA%40mail.gmail.com.
