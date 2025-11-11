Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBEBZTEAMGQEWEBOCIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id B3225C4CA03
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:23:18 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2956cdcdc17sf50425805ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:23:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762852997; cv=pass;
        d=google.com; s=arc-20240605;
        b=CJedgQrCkx8j81mtkZ3qPYfCgRP8lRMpwzPUn7ckTp+ZMr2vBwWoMFV+Kp5hvpQV3Y
         UvFD9JL8zUGjNqM9rpMyagdQdHkYQlvUG7fEDuZ5iOIvoWKoZR7n7fVZzUVcq6gfwisY
         MFyhmcscmk4fsx8IfwFpMEWLkt3KD+l67VOVc4MEU8UHH9ohKLrLwUgCH0myT+guTYYS
         crFomww+qCnu58mzkOQ7c1K1w8JOEdIF4lHj19tQkGxSKr7l/j9mm8JgWux9LOhg8w1l
         eT5l+qZF8tTohy3+wY4OKPUn1cFyiJMXyhncfCXWtEPc6CEQGs2ZPrFHImq2wanVzGts
         itwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zzzVx/pgcg4tot5WdHDsWY6d284ghtDIqiP/xzk5B+c=;
        fh=W6b0kVLPaQnuEXAemV0vWaJCGSy5GwTgnUz6zgEuznk=;
        b=Rkst9mas4x+FtwWaJYlWncin/KFeZfUNVrcR1nXcuL7WmjjbvhaCvnS/NyWVWeMNct
         zmPhuVx4q/AD/rg1MiKvlrFHZDoLgwzVVX19RtWvdj/RYGctCLuElPYluS4sRuQu2g7K
         2VvYWFY0iveM4oUpw8jedAPutcJ+FjkgPOn/ZP4Pu3F6GgKk9qK5z0d1g1c6xEUOVrPs
         iigC7N/3tLql+JFb0QKWnqBExoYWjsypG2eSEXsD/YoJ0laJfIwVciGwBqB/OuoNlQeU
         3qipfXuGioKxlUMdPcN6Rlvo2qWjljr3ISmftcn7nRZPZDy+qggiHh/kfA0DIfN9AhP7
         jj8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g+A9aIS4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762852997; x=1763457797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zzzVx/pgcg4tot5WdHDsWY6d284ghtDIqiP/xzk5B+c=;
        b=O2QPZ++O2bCy/3j61wPslgJsXmML5pW0FS5+FmBhv1PJDjQepHmv25ebq3iSdr5aBp
         Xz+gHyaZYafqGOsdI6EEvzXM3Gk5Fcj7mIt3tnuaEbTNmAoMcCSiXg6vqgUSSE4du1F+
         83bNnDhqeOvy8Iy5tmBC0oAP5Rm3O+Yw4zd4YgTPXLRI5a7SFNMrBnLvze2IjzCxj+uo
         cfd7nDRCldiqeZPAEG8qKutVpv1pcxTH82ly/VWHVuTLD63ljfJMZvuaNc2sDdUtmLTE
         3NuUrgoKv+V5IPjLXDtQpOGMjglxXykb1szpNQ22F9gbDmk4SyV8yhWfs3V46iXDDbgd
         haiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762852997; x=1763457797;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zzzVx/pgcg4tot5WdHDsWY6d284ghtDIqiP/xzk5B+c=;
        b=aTziphiZNNNO82LkM0ynbrTWgNuFma81ICdb1esPCDtAyyMtphP0e14VRIJladh2uc
         b07J1z848LINS6qTSERLQl4uPV8NAZccj/zkTELMC/ewi1XptHedizUIHX3OYx+3sFcu
         QiNrsO1Mp5W4V/VOwg+NyjOgPTEt+uV9n2rOWO8Cd806e8lxtuYUViOs02QIWZQKsKZZ
         BClp+24fZXZlSK6/+A7wjfGP6twvN4dVQa533RsWFc2GUuZ3BXpDXEzMgXuA74ucHnso
         DiQ6I0B/KUjxTr8dOwv1yMIXXNS/IIZsrnZzIhx3n7dE6wbkHR9Y9y5ubO15FYnI2Us0
         HzaA==
X-Forwarded-Encrypted: i=2; AJvYcCXXs2+fSyH/b7UtvtzfEO2xQukc0nxSkYGK462m3ewJizyxqrWt8rmqt2l6XPdoa2s1vuQzdA==@lfdr.de
X-Gm-Message-State: AOJu0YwzNnEkzn1NxzzKMlDLtEPWbsI58sCxf8MVNC1m9y4SuNWUASDT
	nSz6I2MjLdGp+4B1im6CJL5kS5e/SUDjsXJdqe8iDxPjZNbxTvvOkarh
X-Google-Smtp-Source: AGHT+IGxdiTtJxasLtDVTlVRNp3+KABPVjC0JNZVvYq8C/+xtJ0/AGAiL2jqi+tK5/wmNXFi1msJsQ==
X-Received: by 2002:a17:902:f681:b0:295:5da6:6014 with SMTP id d9443c01a7336-297e5659932mr153767305ad.22.1762852997107;
        Tue, 11 Nov 2025 01:23:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a+gza7E5lElBF1nilCMvxnS1yT7zn++tqtVSqvQ+xKaQ=="
Received: by 2002:a17:902:6946:b0:295:ed3d:16da with SMTP id
 d9443c01a7336-2965264fb9bls30634665ad.2.-pod-prod-04-us; Tue, 11 Nov 2025
 01:23:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWCteVAeRxfX7oFKklGJM7A0KJ1cZgRN1vmWlxPHtF+mMgi4jrVhqcN2KTSEudqoYO1cyh5JCrx52Y=@googlegroups.com
X-Received: by 2002:a17:902:f551:b0:298:33ce:2a91 with SMTP id d9443c01a7336-29833ce2c33mr59878485ad.54.1762852995784;
        Tue, 11 Nov 2025 01:23:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762852995; cv=none;
        d=google.com; s=arc-20240605;
        b=e1/nwpKx/q4D2bKLZJb0Bo055WZLg3JaVDkwX4glvxN0UFMWmP6S/jA3/Ry3Y0cw45
         9WMNrX1cX591mOUUecgl3A9ZN9rkDH/qzgUdOK1xnYAi+kAocMrxV3vfxH+60Jt4dWvx
         k7+pRRdhNmD59D/8yvnadh68FeeJjprMTQTqeHnQST8SQXQb5zsG6ucJ0PkvQea07Cs1
         LSXxhpK4zyvoC21hJ03z4YXFHo+2DJkefWHKvWDLiI/9d7DrD6SzUL9e3Etrbmo7cZMY
         cjGXOpac7ak5Maeamg+NgCfYsfU2VTKk2Meb11lKBk6AaE+g51sOzEjx2HJrrzIN166N
         CVNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HW+BHIjHuyTX7OAC9AGqEECbSB0U1bNiaGYXhX8ud1c=;
        fh=GfNBBti5ikSf1dNe2L1MGadA7b42bDmLOV2quEl67ck=;
        b=MkeP3PSSVYdDd/64ILJ4cj5v47nJwgNfXvj3CgPy/ocv9mNOeu4DTbaU3RWaKUy77W
         p79t3Hkp288dVGS6mkKWpL/7CpDAc1inKwrEILE9GRw51cpWt+zDQhskbSz61uXteh4S
         MuH/hbENODi1T/p8/pmRzMPaKkiOTPDWO4q7k4G4NIrd81uNJ9FCIyE07dgtErFSUjzt
         FC784HiejEFUA9DmnC53L1h1DQsyR8zBMvrjlZaIMT+qHgfo0m+ClviT8JoLOMJWDOVp
         UHzqV3+ITS1HDJaUp+PEflfb4nDDuEOzSHyFH9tfkKOHMqEPOMHNU3JpxlRwk8M1v6n2
         3RZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g+A9aIS4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-297f92fabd4si6499055ad.8.2025.11.11.01.23.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:23:15 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-88054872394so58396696d6.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:23:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU8SlA7yfEmxHyYuJY9u6YHya9kBZV+nWgsoqILjog7jyusFrI4styn93FU86aEgzYv0fW6arqxA3g=@googlegroups.com
X-Gm-Gg: ASbGncv2YvkzR/gDEXPdW3vvMP59FW7IE4hEFcCpPj204JG4gB+FnRnBneFpS6nE5Vq
	jy69kFhAcOi1jn33nhS9ribNtM+FG0G6ja8zeM1EJ7TcN2KOHPMEUH+wub1cdlOv/atXV5L2OhC
	ad9zVwvFcbzwBj/uT6eBcjeXUZupyX0TvRCdZ46PUMPtLVzAjh2galGq/E4Gsh2JUdDqcRej/8z
	fsyx/42AEEw22esXst0VibOwVSsX/BSk5fkNsXTcb2hyrKy/GEdOG/TtbzKpaX77252OSlUJWvi
	Fd8Sx7B+clTUXzIG4lzq7Kc5Cg==
X-Received: by 2002:a05:6214:1310:b0:880:3e92:3d33 with SMTP id
 6a1803df08f44-8823873d584mr174202246d6.34.1762852994390; Tue, 11 Nov 2025
 01:23:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <8681ee6683b1c65a1d5d65f21c66e63378806ba0.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <8681ee6683b1c65a1d5d65f21c66e63378806ba0.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:22:37 +0100
X-Gm-Features: AWmQ_bn-gtNt_PIr26xFMqgMDiPlRCOzgcJVubPfw4RNrG4hXg8UIUOVQ0zkb_Q
Message-ID: <CAG_fn=V46UeEvrPb01VRk+60-wL0DA6Y6ZD5HAfVLzHcgRh+VQ@mail.gmail.com>
Subject: Re: [PATCH v6 05/18] kasan: Fix inline mode for x86 tag-based mode
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
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=g+A9aIS4;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
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

>
> Explicitly zero out hwasan-instrument-with-calls when enabling inline
> mode in tag-based KASAN.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DV46UeEvrPb01VRk%2B60-wL0DA6Y6ZD5HAfVLzHcgRh%2BVQ%40mail.gmail.com.
