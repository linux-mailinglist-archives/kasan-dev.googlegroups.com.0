Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU7XZPEAMGQEQMQVAUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 9060EC4C82C
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:03:18 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b55735710f0sf6953438a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:03:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762851796; cv=pass;
        d=google.com; s=arc-20240605;
        b=bsYFJyjQjY0vB/zR1dnO5nvxTI+HoKp4vQs9nKdSSn7Px4ULNZoOKrrtn6yvRGJSkD
         Zetggaw2AGzqaXTZlSRwcJsNigG0VI1yqNtQiJnfs/hubcyJVOVbjkBCP/RVNR9sAeSL
         5z0pxXsEetnQycku5e65/myt8HPo+AGHKIi+lJdrJt26E9aa9I7DUZArhEK9Mkl1QYj+
         OFJb2KK0eRYd3SvgATneXWDRSsZsOopiVoVAcdPuIwZqTUCAb4RF3BqYipPjDrvOzfH3
         lpD5QCaoQrEtQ1k7X+mgqQooo/+4vb0Zet813Wy14cO9H1aDBll+rgGxxdtqG798A5cl
         BdlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Av6n/UB3LJNIfX6jPfUI1iv/ZJzTnxMuCTEUlbde8Ho=;
        fh=MxJkmrocKqJnQK27/VWbXZuXgOJWsOKAS0TllE6Ja3E=;
        b=kPCC0KsuUvk3L8QAIOFV12Et1QPnNFvvHeq9XS2T8pOllG0FfN3evvejC0Th6yZnmn
         oO+YsLqY09aAON3QVRSMCbhKEatBQCW3tlD8Bbk1Asdg7iXkLa3CL3Zhw0/J9aMy4F5S
         CXwgqUvgQd0J31zfCQ0HrryzLWnRdMMLbePZtzXdrCvd4V5GLv2zsAW6Z/hlveJhMfSO
         t/eHE94bU1e+s+8DQxife/0Hgqlq+Q/vvpF371iQ/NvtiuuydDYrGCE4RXbtOWNr6lPs
         3cSMgEQceXOmRNY5+exzF6ZskeVLARuO/g5plefAE74whZdsW+H1H/Sy3xThkyJtjjTf
         5lhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RtLRoL4h;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762851796; x=1763456596; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Av6n/UB3LJNIfX6jPfUI1iv/ZJzTnxMuCTEUlbde8Ho=;
        b=qwo5LSQuERDwCzkbkBt/A4rEAzes5ZYpYLLKodZ9WE7tod7Fp+xZ9eWZodwxyxuDZm
         nrILaHpl//RX/uISnwweX/CZ/p+50geshsUtZjAO02D7oC0y5fu8BmOuFNd3VV7buUFq
         RKNu+wIaH+qPJypQjDMJWpUF87QkBGXJG5S6C4H1TW0083Vr7U+dQpwBJcOzKxOd8CzL
         NsrumkJgFVNNVnvKtxx+syW5sE+kPFYz8lFkvbtRfk8z8/J8K2TYFvyoKqAMGHfCSUsL
         SirjZbx7OZcshN9S9Aj1vMMBA7KfGQkQ7bKct8i+xTq5Jh+VYgRAbMmOozD1JhClZp7n
         WDUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762851796; x=1763456596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Av6n/UB3LJNIfX6jPfUI1iv/ZJzTnxMuCTEUlbde8Ho=;
        b=dSRw9vgtdqJqYzh5HJ27KCGbJBZrKLjb9w45y/1hYZYufGco17+Q3Jr8OTdgcY7GcD
         7YZNMIOp5tK94o0EB3OLv4mxbTcb767m1coybM6JILnf08948Cn9FHA5hxtdjB55FGSG
         G/5U37o5QjFwfqu6S0Ve4Nq+jubaOJtBnXCs4ZdwTWCm43k+/QUbDMwDDdpyfpNAeNNX
         RXEtUlXdxfWUUGdssioaYUDlVRg2aEh4wKlh9o2EUiRZgLfu3mZO9NhWtnOhP66sZIOI
         TNEHzLe5QkxjwK+uSwWRgjhZ+oxc2iztM99tziQkggXRNdl4kxeZ8iGAaq0hGwTk5T54
         kXaQ==
X-Forwarded-Encrypted: i=2; AJvYcCVURWPHtjj39FFM1XjPso77Qk48X8EiMDqcrKZl9hCbNhOUUeEwYzST88wYhdLn+ruu5oubKA==@lfdr.de
X-Gm-Message-State: AOJu0YyeiYKGuYqixEbuIyOhLX8gMAAWqsczqFOznCYM6xr4KtPiq5t1
	k843NADJShDF4YVDtBHobIYfDRWvIpkwXZ6mMQOkVG3+IT73Ht2t29qc
X-Google-Smtp-Source: AGHT+IFsXpZr1GS2deKC4zj0YHaH9OHEDaRMUVoFVhl3zwmVjNin6usksHBJ0MZRvPuSSgi8Sw+Y+w==
X-Received: by 2002:a05:6a21:99a0:b0:33b:4747:a258 with SMTP id adf61e73a8af0-353a3c6009fmr18275626637.46.1762851796359;
        Tue, 11 Nov 2025 01:03:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZRNI5+xqPqwKP96vEXi5S4rGf5eEHWzjXTgLZA4fmPEw=="
Received: by 2002:a05:6a00:7701:b0:7a6:a380:fc79 with SMTP id
 d2e1a72fcca58-7af7ca01cd1ls5499979b3a.1.-pod-prod-06-us; Tue, 11 Nov 2025
 01:03:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUSIUQCdRJeU9j7n9nj95S2KNsdzCEzdDiSVC4SQdGDKZBwe6NpNXJk+KJLdPUYaLUl9iYlZDwP3Yo=@googlegroups.com
X-Received: by 2002:a05:6a21:7747:b0:355:1add:c298 with SMTP id adf61e73a8af0-3551addcbfcmr8842913637.21.1762851794945;
        Tue, 11 Nov 2025 01:03:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762851794; cv=none;
        d=google.com; s=arc-20240605;
        b=NfMS62c+s9HnybqYhOmVzEH437KJXbnQqA4dW+ztYN3dOkhpO4C+NBJBEW6Vl9Zlrs
         2EUjNXm+dIQ39RDXfvqfJB6rRtJ5goyK/kwNjjv+MfXCx8rFRX00EWikgfdFnA9ad5CO
         YQyV06JUBTNCQgmpUoJ3f0C/N7Jj6KR0qmYFjgbzZdwYoqCgirFrdh5Vh2a8W0q/H1cx
         V5xOydYvYIx9+XDH2+Ww2YvOJ7b+8XOUuczbhGuN+3goCh0dpwAierAgL656IZtBpD4O
         pr0KfZfyXYtWGVZvcPYqQqbGanBkFAWFQl8iqJzrFqTJHYLFA8czZT01J5401GW7IQk+
         AZlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pvNoy8QjEGF5vDREzb9JJ0U69eI//OHw5iW0XV0TScg=;
        fh=xxRXBKdyyupQ7LCTFR75JNQtaRojGH5gB43VXh9BEI8=;
        b=I82X8wfrDVqqfv6606La9eKTFMmJU3iIA5IBN6e1hQbM0A8xNgXwFEXLI2Y4wbJwM/
         JbastWMfYVbMdoWSfVINDBU8brBHk2ja8UhRJVXlAsDu6wX6J6K4O9CSEtCYy7Bsj62g
         Ok6OFLqjJbVGJsYTwNnFpd96Iz8C5mbb6gRvSMgcqbx//GXdwJ+FbDJ/P6YW5vzmmWZC
         2opJA+xT9paMxn+86uyvPMMDMjFguSpj37JsrwF3pzprLmsfG0brHZVlPP4V+nJYP9JK
         qcnnV/qeY0aql8GrP2eUFS1GqgPBaPJMdWkLZDlgV2cyszw2TUJzeiW9YKc018k9gSzb
         rhnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RtLRoL4h;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7b6ecd76cb3si20279b3a.5.2025.11.11.01.03.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:03:14 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-87c13813464so51128886d6.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:03:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWmc7V7bfOkUcPNwL49Agv3u4K+XPe69EGxOXfV7Kh49njrBSbWwMoyTlWQYpVrHmpOgrRnyGNbvR4=@googlegroups.com
X-Gm-Gg: ASbGnct/vfPw27a+oO6/Z1WXUbcGN5ujzmUxYWQA0sJFiaHPtkQW8MR+qPDAY2YVvHk
	HvoQUmGeW0/+FddD54Qr7GXvneCnSIpX2TnVqFTptwcjEhMUUe2QJSOPCzUJ60XHDgzsmsSD89F
	e/VwS4yZbxYJTZ01pEWCFFPyX/j+pLKdzot2ACWQqQa9w1l7cqmidi8th1+9jEvlg+0rBnN3S6b
	Y4xvlr/nKyWCmw0tdBZQKEpaEmbuhoLYHRcLdFXHSSFEQTkcokBmfb+MKfpXkrWBtkv1mhnJ0oU
	JwWTFON/tLKjguZciMXxqwfV+Q==
X-Received: by 2002:a05:6214:e42:b0:880:51ab:a3e3 with SMTP id
 6a1803df08f44-882387621d9mr168741746d6.67.1762851793588; Tue, 11 Nov 2025
 01:03:13 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <0a21096d806eafa679798b9844ec33bf8a5499a4.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <0a21096d806eafa679798b9844ec33bf8a5499a4.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:02:36 +0100
X-Gm-Features: AWmQ_bncs5LVtJN1ReProGRqJJIZk54xNH4kh3rOCX8uWFHvQkLT6YYoepdGREs
Message-ID: <CAG_fn=XQPbZb4MTBUgkJ17gfQL5K1QMahaJ39Mw7Hv4zm1crXw@mail.gmail.com>
Subject: Re: [PATCH v6 16/18] arm64: Unify software tag-based KASAN inline
 recovery path
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
 header.i=@google.com header.s=20230601 header.b=RtLRoL4h;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
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

On Wed, Oct 29, 2025 at 9:10=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> To avoid having a copy of a long comment explaining the intricacies of
> the inline KASAN recovery system and issues for every architecture that
> uses the software tag-based mode, a unified kasan_die_unless_recover()
> function was added.
>
> Use kasan_die_unless_recover() in the kasan brk handler to cleanup the
> long comment, that's kept in the non-arch KASAN code.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Acked-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXQPbZb4MTBUgkJ17gfQL5K1QMahaJ39Mw7Hv4zm1crXw%40mail.gmail.com.
