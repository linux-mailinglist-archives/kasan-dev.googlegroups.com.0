Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVGBV7BQMGQEYD2NBFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BBB9AFB6A0
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 16:59:35 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-234f1acc707sf21745465ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 07:59:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751900373; cv=pass;
        d=google.com; s=arc-20240605;
        b=LwpVQ5TMw6S+V0nldu/Vl4oWpuv7066f0BKuVcvW2vSnbZrE28i3JS2SFV4KE6fgN4
         Ior+JE3Lsm1LggxGyrH4Ke2Hm5iJDa2uUJ+fCOPfMKGbW46/uFOWfsXeDLN4Y4L+VZcG
         AAkq7PR+cVmyna5fF4kTR1nEFRRhrbC+ulyH/N7CV250yMn5yE6I93y5kKXTlpru8nbT
         Tz3fsU3bGLgx3NgY/hTDZlCp7uAD3lRuEaXxt/1uXptTdZ41aY/VNwCUOOsCJIyvFm6Z
         2A4HmvAA/kzyVEJsgIwV5u5Ymg1NZ3R3xd012IhNx0n6dNMQ4pW16XfVDC8MzPlFXhcR
         5qsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=94UmHnllMgNf32ale3eHG6sRvruGNU1yfC+y0d+tdPA=;
        fh=lOz+2q5K7G6Rej4YwcnmkgtM3+1mOOo+DHAXHv9z1aE=;
        b=kPmmxqv/DN4G1Ljacr8y9S0dQoPlUmkCFu9WV7sSmW4tfBM4WkQJ00Lkd9cuCxDZsB
         IC0DOiujyzIjxe6sUkXfJ70fmJLlmGbea+qT0Ag7BAcfZzFeDymsRmA79XqgCAK0HFVy
         dnHkOAagkY2q88EtTD3oJcD/uvgZLu4RkyTdM8yfQcS53JZrprvZ1xIPXmcFha6W+mWq
         ZdsbxdhADazbB/ejNRReFmYfChFymuR4ypt0yNGL+1KUV+xjgwoIdP71D/BCcntv1iMh
         /fV/3SnvVPQYG3OGCEcqAUGmfqS+aCFhjUxJFB39Qr+GyP5XJUfuaRBCGuaqkTHeiC9E
         2C1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HbpQJbd6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751900373; x=1752505173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=94UmHnllMgNf32ale3eHG6sRvruGNU1yfC+y0d+tdPA=;
        b=f9xa3ruaAu4lqnDjER9hrz0KmbcM+CdBpZXdcxZFjiD3UsyLyIvc2b82UBah37B7xW
         4G+Zz2fbFawgeMOu2G5B017MbtgO6b0csAptO2MVM1TNM09HFN3o9WslZJ6esK2UHOFt
         tPOH2Nfz3ck0eXJf/T8JecH4aDJp0lXyn6HCGFgGK3vAtRxoXM8zI7IdzA8LAaW4PxAE
         myjqI47Szr4Xx2JADqleoxuMrcMqdqq1pHRsMR2s2Cdngg4dX8J0raYbNrVYhDTAXFgh
         Js3RBmXf3AurxM0gmNlBZiNx2p+5DGgCA36Nx19oIEH+IpjgoH6fnh9Gw0MCtWVFR7M2
         r1xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751900373; x=1752505173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=94UmHnllMgNf32ale3eHG6sRvruGNU1yfC+y0d+tdPA=;
        b=tEwPgf3ROJ5Y3Z21OQEYvsHIMS83h8kQMCxJhsdRl2oyj7WWanMNdYSkLeFQqU51mx
         cMp40Vt68IVzCWWS+aZGoxN37FfMGTk9wr5NI092FMo1Ek7wguka1Txa/dbnHSLHGEne
         vwyBg+FNDveaYwOkdG85CnTiPgawVs1F5qha6+SGFNYBqh3rjb7Itu4p6M7TL2AiRKGA
         g2afBavmDQSIeLJ4JUMmSXfuB1W8h1kdDsQL8XMj9WMgjJBlgJpK84V62AUxj316mcyR
         cy26Uqq08wulAtaIanZMOF7irs5PhG5qEaIejHFG6ZtrlzvWxDzkM3k1x1Wot/I2i5ct
         TC2Q==
X-Forwarded-Encrypted: i=2; AJvYcCVM/DaN/Ba82Dou9keHp32m9geKEsIN7cPkxCyn6BZKyYQ/LILi4pMXVMxIHKdfDXyM5ZAINg==@lfdr.de
X-Gm-Message-State: AOJu0YxdB/8rm9z/xhK1iEYZASJEWW7oF2q7B1/BoKna+E0+5KHxFSg5
	Kd5Xi/C2WURWEX8vyy1GX/GLrylrp7KRgY6tjnnrS5FXwxWoBaQV4Sbn
X-Google-Smtp-Source: AGHT+IGHAAt79XIljCWQpFRCLv13GEGdnidofYdhUoL6h/5bhtSaUt8Fd3KyTc3IMdsbA3tjAAZ/qA==
X-Received: by 2002:a17:902:d587:b0:236:6e4f:d439 with SMTP id d9443c01a7336-23c8747edfamr155954625ad.23.1751900373284;
        Mon, 07 Jul 2025 07:59:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdUP6dDkBGdAis2MC9e62CfsuCPvdNWZby/WPriVNTMWQ==
Received: by 2002:a17:902:8b84:b0:234:a07c:2698 with SMTP id
 d9443c01a7336-23c89ba2f74ls22159975ad.1.-pod-prod-07-us; Mon, 07 Jul 2025
 07:59:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQqsEZOAZz96JFuPLIKU0ua742U/oUg4xFQLtEqDVv9bZx4yh7+I4fcz9GTEcPFDJoyWAFGnFv+2c=@googlegroups.com
X-Received: by 2002:a17:902:ecc1:b0:236:748f:541a with SMTP id d9443c01a7336-23c873ac226mr189142415ad.0.1751900371071;
        Mon, 07 Jul 2025 07:59:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751900371; cv=none;
        d=google.com; s=arc-20240605;
        b=WydICcWm43zeZlPU25Q7r4U1tcaGYSIvTkBDJ6YFqvVUcPrRWElpG0qz285xYQuPCI
         3jD2n7zbYtOfCTrhrKb9+Oew85v04HYBPsd+V4eObU9xYXqySkKYP0fttO5mcFyWYUpv
         lHD3UP86guEY6HnXplMaY114VyyTjh0O5+3mquFup3TBnynOqoKMs2iGZ7MZgePfszbX
         Q+M3vHjctWgvRQI6ttg/LCZdGP08kybUcPV6SM6eu7+wKTJ8DFL4hPXQe1NCUSjFyvDB
         b+QtfiEmPhlP1KTAJqPgSzp2D87mKCwpjDuoglOLAekazLHwFM++B7eDPjMGcBvqqpwI
         fkyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6TQLxoKJTtnPQL66AOVz1qBZAurWsbbtmQ08gZuI+u0=;
        fh=AkOEw5HNxcBtnmTrlcpe9G5DXHpnmIOGEa7/8sWMgPM=;
        b=X/TzAEjbbMrdF7A8RFAOD2Xsg5HGDFJKB4rUwRPa4pfAZhzZe5/ailg+3AfBE5N/t6
         RJw034TcPZT6Ui4vBQIoQ0hFzsV+v3snKES3OhUHH0gl3jatHe+734RzPaYYwXUyzlov
         oFkXmUt28o7XBP2mbeBSA8JtKfTUwIF/p2UB1XJ+/4zioeV5mZpdN1Pg/q8dVYgkP9HJ
         udxKZtltR9chY36qAB2nycdvpuEy/R5AfAu0Jbkz9NoZxcomVTUiT1u+ymJ2P9qjwVi+
         RTn77oOlGq28Yd99NwZW3ypJLkorqyEm7O2fdsE8hnttcETObzxWhF5wmf3JZevd1HYs
         R0gg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HbpQJbd6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23c845037bdsi3348405ad.9.2025.07.07.07.59.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 07:59:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-313910f392dso2621348a91.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 07:59:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWL6fTBjNiZh610lnV00BaJPP/YzudsPe4pdf5nGnyxHz9iSVMY6UBgD92FFX/PHG9+MPT2huwHi3E=@googlegroups.com
X-Gm-Gg: ASbGncuspiVKrvQFTx7lki6D1WntbGIVwghEf+Z38JHe7koP9+xBZY016P9oGXZlQdv
	6s69QNLBCuqJa8b7vCjlKEOhL+a6C1xUdP4ZIjsGKZB7nDI+eLXXnKkxcLMK1ZsR1qBdH+Zose3
	kA/n2puk8Sw1gICuB03B4v9EhwCk6Cd3+7lPu/Lx//
X-Received: by 2002:a17:90b:3f48:b0:312:b4a:6342 with SMTP id
 98e67ed59e1d1-31aaddfc24amr20985661a91.33.1751900370388; Mon, 07 Jul 2025
 07:59:30 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com> <kicfhrecpahv5kkawnnazsuterxjoqscwf3rb4u6in5gig2bq6@jbt6dwnzs67r>
In-Reply-To: <kicfhrecpahv5kkawnnazsuterxjoqscwf3rb4u6in5gig2bq6@jbt6dwnzs67r>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Jul 2025 16:58:53 +0200
X-Gm-Features: Ac12FXxNc7MVDdqbSkiHg-OPuizBzk24Lc8ThBNq8a8QxrLwekty4YemWnP4YPo
Message-ID: <CANpmjNNXyyfmYFPYm2LCF_+vdPtWED3xj5gOJPQazpGhBizk5w@mail.gmail.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Chao Yu <chao.yu@oppo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HbpQJbd6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1035 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 7 Jul 2025 at 16:39, Alejandro Colomar <alx@kernel.org> wrote:
>
> Hi Marco,
>
> On Mon, Jul 07, 2025 at 09:44:09AM +0200, Marco Elver wrote:
> > On Mon, 7 Jul 2025 at 07:06, Alejandro Colomar <alx@kernel.org> wrote:
> > >
> > > While doing this, I detected some anomalies in the existing code:
> > >
> > > mm/kfence/kfence_test.c:
> > >
> > >         -  The last call to scnprintf() did increment 'cur', but it's
> > >            unused after that, so it was dead code.  I've removed the dead
> > >            code in this patch.
> >
> > That was done to be consistent with the other code for readability,
> > and to be clear where the next bytes should be appended (if someone
> > decides to append more). There is no runtime dead code, the compiler
> > optimizes away the assignment. But I'm indifferent, so removing the
> > assignment is fine if you prefer that.
>
> Yeah, I guessed that might be the reason.  I'm fine restoring it if you
> prefer it.  I tend to use -Wunused-but-set-variable, but if it is not
> used here and doesn't trigger, I guess it's fine to keep it.

Feel free to make it warning-free, I guess that's useful.

> > Did you run the tests? Do they pass?
>
> I don't know how to run them.  I've only built the kernel.  If you point
> me to instructions on how to run them, I'll do so.  Thanks!

Should just be CONFIG_KFENCE_KUNIT_TEST=y -- then boot kernel and
check that the test reports "ok".

Thanks,
-- marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNXyyfmYFPYm2LCF_%2BvdPtWED3xj5gOJPQazpGhBizk5w%40mail.gmail.com.
