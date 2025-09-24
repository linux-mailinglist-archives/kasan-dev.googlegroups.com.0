Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBG6TZ7DAMGQE6J625NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DD73B99EE4
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:52:45 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-46b15e6f227sf14002665e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:52:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758718365; cv=pass;
        d=google.com; s=arc-20240605;
        b=km0z2GvEN4YOPAfXtCnDyPT7YhXmkBZO1fNlSDeat2W7bKHk13B+HE4VgqvheJWI6K
         DP4WpPBuXW2t/S0CesFFL6bJDSxoa0eqwzKxACvGsobG6ZezzgofQOkyDy6yUP5CDWr0
         4LPdmF2Ykdc15Z0k1wIkhz4zjstnetTKBLUbhhWp67CvM6RUhwZCx1Zhn2M6fWmeCp+i
         6tIsZJ3ETZG5xYUsu2KgTgKRsILqgn1LZ8xp3RzTs18wtuqTZFCfB5r0Zg3+JA0gr6IG
         CrbwJ8Q+8VC2lFgxOX5SZ5S1AmBaVpKioBhmt2y56R/ZdmRCH9U9cOxcdhfK3Np2OnD+
         PeHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=srE3khVDI7LD9h6Xf+vjLva/immQOuvgByvklsLAnbE=;
        fh=X07mBAJgkINvcsU3mWhefhgtajWku22bfnOLfe/ZUHs=;
        b=CoCgD4XiIIcI/pir2gNb0fD3zqx9DQbdx66ndxkAx8aztqwjtZuTGMBXX75lsK2yfv
         93sFN9YKNosYDY5sFF4yt14XG8Isd5BefoEpSgqhXq2lAhB9hrYKA33IzX4Lr0wFFnYu
         nbC9kHIAMfGoYkPChdiO0hLA7woBEnSrGjKZEKBN+6/qWs3lwTx9+21PU4X2uAqZYlFc
         +OLmvjFySQ51Q5TXd+pv2odnWCwkiZKdwiNTvsPJzVvAD8bEV8e2S7JI94WjPkfBcoM4
         u1Jn7g/4M90jN5KCgwPjjU50F+XpAqvbGjhA9Zg1XycqdIJjtQ07onAVMNe+dnM/V0fW
         AZ5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=YbRceCCB;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758718364; x=1759323164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=srE3khVDI7LD9h6Xf+vjLva/immQOuvgByvklsLAnbE=;
        b=PNsacfyIpjU1GKXNe2zeRxFCEX7ljUuukFgVjsP51KVKuJpIFnL4ifrjkwfJUjT/zi
         jzoaklrAUigYTtiXry2HtwJltNhtLkPrCE8RuoecVcYQXgQdtMc2g63QN0rnJf5fYxcP
         Fbip3Aalgx6nWieZF3Xp9HAPmpD0k4oke8+VJdZum+yVdweqoa7D3GNjDV30sZ//gujm
         EYuLc7cK1n8MJkkJ6obmWxh4HWBt5Z+I3O0l85vjteL/ps9qMDXwtcP/COt0GdNBn9u8
         ZUXUljI/c0Qb6nL8jmUjRkuCinff4KDPli7LaEjmEnjzTcEGbIOlpdMCjnWSnwIfpBLJ
         iYTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758718364; x=1759323164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=srE3khVDI7LD9h6Xf+vjLva/immQOuvgByvklsLAnbE=;
        b=sXRgBmTbczWrMGPKIL4beJ/XW8hVqUhZMlzUxMn0Ym8aAgTN6W458zoyNg8y+4pVaH
         QcJ8K7Q48N1Dy1+rvczpFhB3ju6EX0MGHpULoENy9IUMn9KcaTdemAYxuggWtTpISP/6
         ssJK6+EJrFhbDwvVhSj3p7vYKpDDjhWAQQmqfX5Vdl52E1tY/kedm5r5rLOc/mGSF4U1
         0MDt+T1aUpDfgR3/IBGf2pZJaXahnjkn41vglag1thlHAYFQV8YWaYF4L6siqdNTqlAP
         o2hSG2dbSHoY3b1MzcjWMmrDZEG86oFvEUPmnDP4+4KBcbNSdroq94yr1O6gU5Ov+HWr
         fzmw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVT+gxj2ZELZrntJ1E1vhEqKGRS8UMq78bJQ5/Qk96IPqMwJiiiFWMb+JoEK1fTQg9790mjHg==@lfdr.de
X-Gm-Message-State: AOJu0Ywj10mMc7YzB6hWJUdqPHgMjr5VXyFUBWr0Jasq3tGmkeY9+nAy
	1N9N8bImtvNh7bg118/d9CgNyFDELXtjbgd6OVUARYJVzPmb50mha9jM
X-Google-Smtp-Source: AGHT+IEbRmP1yHKZ23nLyaQKj+95jDTjWEYsyjYquyzXuKu+h/MPl5Ez3mYYoCjWGT2o9D9VA3TtDw==
X-Received: by 2002:a05:600c:3145:b0:45d:f804:bcda with SMTP id 5b1f17b1804b1-46e1d9817dbmr63272725e9.13.1758718364417;
        Wed, 24 Sep 2025 05:52:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd49KRE+mSey6tL85wFq8b0C9XPdGB70WquCj2WHvLGK1w==
Received: by 2002:a05:600c:540f:b0:46e:2b86:81f6 with SMTP id
 5b1f17b1804b1-46e2b8682dels4739015e9.1.-pod-prod-04-eu; Wed, 24 Sep 2025
 05:52:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAsFfHquC3s15plDelV7Tcj4LXVojFdCiQ6mLfsUgWzGLY8wVFmnqNVvNzFiB/ubGXo4j4vG8XrDc=@googlegroups.com
X-Received: by 2002:a05:600c:4f09:b0:46e:1aaa:6953 with SMTP id 5b1f17b1804b1-46e1dabe43dmr57573135e9.28.1758718361743;
        Wed, 24 Sep 2025 05:52:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758718361; cv=none;
        d=google.com; s=arc-20240605;
        b=DXL/I+rMGDLajBbdneKbKwf1o+ENn35BkXrIO2AGF449WYClj+mTzc5XN1eM8EcEHB
         2BfS8x5WruEusOAybc/lT7163XkKC+QgFsV1X0A5PAayzFYywHhvVOZxeUvvHruc/LI7
         fH3sNFLbFeejJctuFgCd/n8ZpHruz3Buxt+1ODbkTIAyBJxMDG0W6EJYbSjpsNuvIU2O
         iFRjDAUbp46t4fqur9BvwYBy/cgED/rc911vXYJf6aG5L633jXKT/Clbq1ZW5sJ7nDAz
         Imm/t3TcL/AAE05ODVpkEH3qn/GCGswH44e/Qfb8osAtTjf/7C4hy8Uas8zZ2lqB5PhL
         TQnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=h5K+P/riDmU7tvn3fIuQxPNsf4KltKjt2Yr02gW3kT0=;
        fh=gZU0QbOfDfUHA1yliJKiIafaMj674KUIe0ogWesOIVk=;
        b=AyYbYajAl1Kg/YuAOdNNH0g/1mn9Uf9xWGF9t+x0zjRSSGG0P70Kq56dxBjycDgjcD
         J6w7ql746jcWONLX4xcz3+rHPxNL56ZGnndqSokyPVGKKoyhQ7VpOpuGfBX1aDZCAzLP
         Ch9jScntswlqI7RoFqPn42NR+q2sgNP2tCS6QtCbRHIH9ocZOJeJaCWMPmzaoOSooxoM
         ++OP8wiRXns8+y8N+HoSFTyotHgNlG+WyXsP/y/tS9T61E/IOxNj3C1QwL1QVyixXosu
         kM/MXCsq5bw5F5Nw85v22tfO9jyX+IIk/C8kWMsC9du9pDSU5PXd2JLu5bGHoqQo1vyF
         E8UA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=YbRceCCB;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46e2a7a8379si337285e9.0.2025.09.24.05.52.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:52:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1v1Oz3-00000008sim-1o1i;
	Wed, 24 Sep 2025 14:52:33 +0200
Message-ID: <3562eeeb276dc9cc5f3b238a3f597baebfa56bad.camel@sipsolutions.net>
Subject: Re: [PATCH v2 0/10] KFuzzTest: a new kernel fuzzing framework
From: Johannes Berg <johannes@sipsolutions.net>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com, 
	glider@google.com
Cc: andreyknvl@gmail.com, andy@kernel.org, brauner@kernel.org, 
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com, 
	dhowells@redhat.com, dvyukov@google.com, elver@google.com, 
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz,
 jannh@google.com, 	kasan-dev@googlegroups.com, kees@kernel.org,
 kunit-dev@googlegroups.com, 	linux-crypto@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, 	lukas@wunner.de,
 rmoar@google.com, shuah@kernel.org, sj@kernel.org, 	tarasmadan@google.com
Date: Wed, 24 Sep 2025 14:52:32 +0200
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com> (sfid-20250919_165801_647339_D5FEA55B)
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
	 (sfid-20250919_165801_647339_D5FEA55B)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=YbRceCCB;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2025-09-19 at 14:57 +0000, Ethan Graham wrote:
> 
> This patch series introduces KFuzzTest, a lightweight framework for
> creating in-kernel fuzz targets for internal kernel functions.
> 
> The primary motivation for KFuzzTest is to simplify the fuzzing of
> low-level, relatively stateless functions (e.g., data parsers, format
> converters) that are difficult to exercise effectively from the syscall
> boundary. It is intended for in-situ fuzzing of kernel code without
> requiring that it be built as a separate userspace library or that its
> dependencies be stubbed out. Using a simple macro-based API, developers
> can add a new fuzz target with minimal boilerplate code.

So ... I guess I understand the motivation to make this easy for
developers, but I'm not sure I'm happy to have all of this effectively
depend on syzkaller.

You spelled out the process to actually declare a fuzz test, but you
never spelled out the process to actually run fuzzing against it. For
the record, and everyone else who might be reading, here's my
understanding:

 - the FUZZ_TEST() macro declares some magic in the Linux binary,
   including the name of the struct that describes the necessary input

 - there's a parser in syzkaller (and not really usable standalone) that
   can parse the vmlinux binary (and doesn't handle modules) and
   generates descriptions for the input from it

 - I _think_ that the bridge tool uses these descriptions, though the
   example you have in the documentation just says "use this command for
   this test" and makes no representation as to how the first argument
   to the bridge tool is created, it just appears out of thin air

 - the bridge tool will then parse the description and use some random
   data to create the serialised data that's deserialized in the kernel
   and then passed to the test

   - side note: did that really have to be a custom serialization
     format? I don't see any discussion on that, there are different
     formats that exist already, I'd think?

 - the test runs now, and may or may not crash, as you'd expect


I was really hoping to integrate this with ARCH=um and other fuzzers[1],
but ... I don't really think it's entirely feasible. I can basically
only require hard-coding the input description like the bridge tool
does, but that doesn't scale, or attempt to extract a few thousand lines
of code from syzkaller to extract the data...

[1] in particular honggfuzz as I wrote earlier, due to the coverage
    feedback format issues with afl++, but if I were able to use clang
    right now I could probably also make afl++ work in a similar way
    by adding support for --fsanitize-coverage=trace-pc-guard first.


I'm not even saying that you had many choices here, but it's definitely
annoying, at least to me, that all this infrastructure is effectively
dependent on syzkaller due to all of this. At the same time, yes, I get
that parsing dwarf and getting a description out is not an easy feat,
and without the infrastructure already in syzkaller it'd take more than
the ~1.1kLOC (and even that is not small) it has now.


I guess the biggest question to me is ultimately why all that is
necessary? Right now, there's only the single example kfuzztest that
even uses this infrastructure beyond a single linear buffer [2]. Where
is all that complexity even worth it? It's expressly intended for
simpler pieces of code that parse something ("data parsers, format
converters").

[2] admittedly the auxdisplay one is slightly different and uses a
    string, but that's pretty much equivalent

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3562eeeb276dc9cc5f3b238a3f597baebfa56bad.camel%40sipsolutions.net.
