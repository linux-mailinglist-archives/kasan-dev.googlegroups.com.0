Return-Path: <kasan-dev+bncBDBK55H2UQKRBBOQ77CQMGQENYO6DVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 0997DB4A59C
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 10:40:39 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3e3f8616125sf2493244f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 01:40:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757407238; cv=pass;
        d=google.com; s=arc-20240605;
        b=FzWHR1Y5hgv2AteYqlIlT6ZNDhGzZp0H2/jyDAKaoez2zi1fLIoP+Mi1yTW08KOAhi
         VM2fdgDyinRmbjWY8fu9ZG/zcLA32rZ1kal8JWHT98JogJcawAHyzKN/iJJ70kLKrR5u
         PReL24MxK2rhC2DQ+mKW0sZBY6rgRefHmM/PnibWTfGsEvy+LC9YPkoRuHoWhaoR+KvQ
         Ppc3xJVx6cODaNUlX85h4YIzb9Kb4GGKP9pefgreu0PRFTivD3DgE+miGw7EQ4hr0Xie
         qxEohsbnYyUCpWECC9SnwK73vgxFCWveQjAb52KqLZjyopmVlf2LC+hZBP54xHuboQ4h
         V/Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DZ1hO/IjZTyb5Lz0/GqVLfMpF3TxsUE436Vah9erlCk=;
        fh=JUQKwSxQjNH2ahKxywbphkvHvmxVlOr4HQ65o3b3oRY=;
        b=KXMzimj1H1eu6QIu+B1NVqL0fxh/0v506sWXabTNDVfBSVyOP1N5WKUi8nMMyxJ84H
         KnBvZ5ep5IwTXSorGONYRL/RrQ6Fd6XLNUNQeuFf988J5do26IbBRhtf6+u9mrtOT94o
         jnOC7lrA9onqZas169qVdG9NDIcGed6/EDF+nSYr/XaKnoyQg1I6ltBVaYI9sNdcMger
         Z8cV12RgOlvkf2zfKaPi58HX9TyNz2AqY+fYjwOs6F+ARlVaDolQsCu1eAYH0l7ODe+i
         2PtjVxdbzPOpuLriu7n/U+6qznhD3Jlj8NyBWd6WFVnKF0VWkhhxAFmoXbWblwt7M6FA
         H9EA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=MBHVmkYE;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757407238; x=1758012038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DZ1hO/IjZTyb5Lz0/GqVLfMpF3TxsUE436Vah9erlCk=;
        b=QkNWyAXn9E5m4nUn4zgA0VAXZlyF06kHDe+ONKou3sSiO2iLy56jjf8Kbg9tOk3tzd
         1NUgrTgFbLlGC7XrRAhDZFc9Nd64rbsY+TcwOQTT8ibqHRKB6YqNFpqcbsft7TxhCxxl
         OP6R8UldlZyVWcrg6FwWadFYdNxiCTi3USuzE4OZILNjaGoWm8B0ak6NPCBN1oyCBHsM
         lRg0eEKCY41jIFhXVs7pO66dfbDYPtM/E5bfWUArRlqpvqMLiGo3AYu3XXNQh+POfzb3
         iong67+kp1SKev4zgLsqhCEcPKNO8/Y7GflbKbcrTqT3uezG+ikOq6qWstAGlWT3mIsP
         mjYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757407238; x=1758012038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DZ1hO/IjZTyb5Lz0/GqVLfMpF3TxsUE436Vah9erlCk=;
        b=O8P6PcZP/eGktkdcXLDc2XZ7myHZ5rlcGVwE5rCHNV4beY1FWCL7QOfFlp83FNI10s
         hU+hSu12f8UL+GwY+EOe6wKvqHV+fC2DWEcwMPGo3eSocXJre+spoXu0Y8oMg8U1bG5X
         8q9C3URNCO8NZMHGpzHimGHuzB33yubm/JV+S/xE82qUWjdU0HLQagQU2B7iIZ6/JCRs
         GK8qbDLcGqRvKVmg0pb/9ZP+X0RyVXwx6FunoL90vCMzp0LbIkOzoXJXicPvPaXBYO+g
         1ua1Fe+n0TFkPoFWkufac43f//7AdKgLue5WSRnvr24lQBAwPyB3bYk5eR8stQ2KLDsR
         BIFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/3zCIqoN/S6av+yleTD58XKd5+wZHIGSAH5RngXgrEzcghs7a7MINoKOwpQTjQ3u8xQsfZw==@lfdr.de
X-Gm-Message-State: AOJu0Yx/mFDXvuIAoDyTUrVLGLr8+mcPSLRuMRRXDuI/U8rNFkZymH4c
	p2p3pweAk+2wa1svVGd1rGzfod2DXOTWSKj9aIW42t3ub+xu48CH5zyk
X-Google-Smtp-Source: AGHT+IHwuZCGZMv4o4lFtisEVlM1BRyyJ/ITHFhcl5stIl9Ijv07XwDnOQqlUiHUFqgXdurymiJgHw==
X-Received: by 2002:a05:6000:250c:b0:3e0:b982:ca49 with SMTP id ffacd0b85a97d-3e627a7cc9bmr9882969f8f.2.1757407238138;
        Tue, 09 Sep 2025 01:40:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5vZW5lJgRif9aP+eHzV8z+N5i4UHTE8oBL/y5z+Fe3Sw==
Received: by 2002:a05:6000:2002:b0:3db:a907:f17b with SMTP id
 ffacd0b85a97d-3e3b5321c7dls1348094f8f.1.-pod-prod-00-eu; Tue, 09 Sep 2025
 01:40:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYSc5cCfSKm6ZLgP7y8JoVNcwvdLEfDxouYgsrI79BZL+RCYSO/zYH6A9djyze73zOUl0fWXdDDeg=@googlegroups.com
X-Received: by 2002:a05:6000:2485:b0:3e2:a7b2:d2f with SMTP id ffacd0b85a97d-3e305d37fa1mr9949716f8f.26.1757407235114;
        Tue, 09 Sep 2025 01:40:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757407235; cv=none;
        d=google.com; s=arc-20240605;
        b=QIWjTeRmE1ecCI/S1OQ2vlM9bJq0yJkZ6x/Xk3Q/FNKGba/c0beFcOZfX0qM86MMzH
         GhfktWjWkUjC9fi72JV5Ptf37+gfGrJfJSMTw4hpGsnJFP/Mw8GMQ915P3CNNfWZJfXB
         ERxCr1QSkm5TQH41hPqjEVNlx0FGGOPy0NeobudaN1kutU9XFVPyuXfTUVJ86sPO+wp+
         1EAc9SgFGZspUIeCQHYUfRV8UVXnxFYQKp0gMv3Rm2ycbS5NSEnGyt1RFIg2fdWksMpP
         AT30xQPkJ5EBUwg6wR/bHzgDq4RQJJLqw/Vb0rgeVhNFS3PwfA7WNyXdtAezvgG3SGh4
         DDpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=EoUcqt6OXqlU+JdoRus3vWmyIypwXpaqFZjRiXTD7KI=;
        fh=6o9exbjceqOafs/JqE/dn63d3bNVOIy3yYCOlKb10pY=;
        b=ZKCs4UoZU+HVGxvnLopdQUGka3iPY04w+WV5ZLWZIlAiPwLvWGfG1cXby2kDLBX1tR
         HRSD6Vpj+P+5/zuVb/tDkJkEfsjT0CjprdH9JpZwMbfA0gPgX/HiB7Vi+P5qBt2vwjyR
         UtecV3hZkNQfGxiftjnHOn0cI0MbVGRCrrCQ9WGmCqKiBBTJ9diB4IO9nx4P5vjZI7oT
         4WPFi7sNnrW1gaX9zbP222oLQckH8pQH6B6Kw9qAY1OrkaRW0CxqbCQmVE+7KpPBVALC
         wpOztmdllA0Sx95Kej8CMQb3soK8C8Ztk5sExX+hllLzlnW5keJiIQpi7iJXgDdj9Alq
         +Dnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=MBHVmkYE;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45defa06864si146635e9.0.2025.09.09.01.40.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 01:40:35 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uvttu-00000005G3f-3VLf;
	Tue, 09 Sep 2025 08:40:31 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id D4F4F300579; Tue, 09 Sep 2025 10:40:29 +0200 (CEST)
Date: Tue, 9 Sep 2025 10:40:29 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, sohil.mehta@intel.com,
	baohua@kernel.org, david@redhat.com, kbingham@kernel.org,
	weixugc@google.com, Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com,
	trintaeoitogc@gmail.com, axelrasmussen@google.com,
	yuanchu@google.com, joey.gouly@arm.com, samitolvanen@google.com,
	joel.granados@kernel.org, graf@amazon.com,
	vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org,
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com,
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz,
	kaleshsingh@google.com, justinstitt@google.com,
	catalin.marinas@arm.com, alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com, dave.hansen@linux.intel.com,
	corbet@lwn.net, xin@zytor.com, dvyukov@google.com,
	tglx@linutronix.de, scott@os.amperecomputing.com,
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org,
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com,
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org,
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com,
	mhocko@suse.com, ada.coupriediaz@arm.com, hpa@zytor.com,
	leitao@debian.org, wangkefeng.wang@huawei.com, surenb@google.com,
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com,
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org,
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com,
	rppt@kernel.org, pcc@google.com, jan.kiszka@siemens.com,
	nicolas.schier@linux.dev, will@kernel.org, jhubbard@nvidia.com,
	bp@alien8.de, x86@kernel.org, linux-doc@vger.kernel.org,
	linux-mm@kvack.org, llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v5 13/19] kasan: x86: Handle int3 for inline KASAN reports
Message-ID: <20250909084029.GI4067720@noisy.programming.kicks-ass.net>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcMV0BOJyvx2nciCK2jvht-Hx0HnFtRzcc=zu+pQSOdVw@mail.gmail.com>
 <couuy2aawztipvnlmaloadkbceewcekur5qbtzktr7ovneduvf@l47rxycy65aa>
 <hw7xa2ooqeyjo5ypc5jluuyjlgyzimxtylj5sh6igyffsxtyaf@qajqp37h6v2n>
 <epbqhjyfdt3daudp2wx54jsw6d7jf6ifbr3yknlfuqptz7b4uq@73n5k6b2jrrl>
 <CA+fCnZdJckDC4AKYxLS1MLBXir4wWqNddrD0o+mY4MXt0CYhcQ@mail.gmail.com>
 <ra5s3u5ha6mveijzwkoe2437ged5k5kacs5nqvkf4o7c2lcfzd@fishogqlatjb>
 <20250909083425.GH4067720@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250909083425.GH4067720@noisy.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=MBHVmkYE;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Sep 09, 2025 at 10:34:25AM +0200, Peter Zijlstra wrote:
> On Tue, Sep 09, 2025 at 10:24:22AM +0200, Maciej Wieczor-Retman wrote:
> > On 2025-09-08 at 22:19:05 +0200, Andrey Konovalov wrote:
> > >On Mon, Sep 8, 2025 at 3:09=E2=80=AFPM Maciej Wieczor-Retman
> > ><maciej.wieczor-retman@intel.com> wrote:
> > >>
> > >> >>I recall there were some corner cases where this code path got cal=
led in outline
> > >> >>mode, didn't have a mismatch but still died due to the die() below=
. But I'll
> > >> >>recheck and either apply what you wrote above or get add a better =
explanation
> > >> >>to the patch message.
> > >> >
> > >> >Okay, so the int3_selftest_ip() is causing a problem in outline mod=
e.
> > >> >
> > >> >I tried disabling kasan with kasan_disable_current() but thinking o=
f it now it
> > >> >won't work because int3 handler will still be called and die() will=
 happen.
> > >>
> > >> Sorry, I meant to write that kasan_disable_current() works together =
with
> > >> if(!kasan_report()). Because without checking kasan_report()' return
> > >> value, if kasan is disabled through kasan_disable_current() it will =
have no
> > >> effect in both inline mode, and if int3 is called in outline mode - =
the
> > >> kasan_inline_handler will lead to die().
> > >
> > >So do I understand correctly, that we have no way to distinguish
> > >whether the int3 was inserted by the KASAN instrumentation or natively
> > >called (like in int3_selftest_ip())?
> > >
> > >If so, I think that we need to fix/change the compiler first so that
> > >we can distinguish these cases. And only then introduce
> > >kasan_inline_handler(). (Without kasan_inline_handler(), the outline
> > >instrumentation would then just work, right?)
> > >
> > >If we can distinguish them, then we should only call
> > >kasan_inline_handler() for the KASAN-inserted int3's. This is what we
> > >do on arm64 (via brk and KASAN_BRK_IMM). And then int3_selftest_ip()
> > >should not be affected.
> >=20
> > Looking at it again I suppose LLVM does pass a number along metadata to=
 the
> > int3. I didn't notice because no other function checks anything in the =
x86 int3
> > handler, compared to how it's done on arm64 with brk.
> >=20
> > So right, thanks, after fixing it up it shouldn't affect the int3_selft=
est_ip().
>=20
> Seriously guys, stop using int3 for this. UBSAN uses UD1, why the heck
> would KASAN not do the same?

Specifically, look at arch/x86/kernel/traps.h:decode_bug(), UBSan uses
UD1 /0, I would suggest KASAN to use UD1 /1.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250909084029.GI4067720%40noisy.programming.kicks-ass.net.
