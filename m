Return-Path: <kasan-dev+bncBCS4VDMYRUNBB5U6WS4QMGQEHWVVDGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 071A39C0E4D
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 20:05:29 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-71e479829c8sf1487465b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 11:05:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731006327; cv=pass;
        d=google.com; s=arc-20240605;
        b=e5g1hkq52/BoiWjzL+sxjBRgBSV6uzlVpgSRN1XGtVyXwEAuQoQGXVgmL3zuzBRQNB
         bSpXOtZG3w1R49Nlx2tmLzUsvRvHMfBCCirMXnXVbOCPTOONza02r+Oj/kKmWTxGjj/w
         ar7eoedUZBHX9GLVtNtN8frG1HGpHJ3o0BYmmsJMjQBUizchLT0bkZ2f3Wh1UWSvg8YO
         oHud0XFM5wBcaQsjn6IIdD/ukycOvgNlD108BSJmRdK6Mpi4LHlgBotrmzaBsa0WG2mQ
         bWuVV/IQWu/yZKQhzFNxaH97xUGAiLD0A9i+kSKqwMnyG1mnlk7FJSormddM4o8WI/Yp
         w3qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ipRByywzxgKsw0MjdrlYqVsp3r9QwKDANgQew0qyHW8=;
        fh=YfVwNLkKYRmZ6Z5uvLTWYwQyXpk1n3K96uItqW+jSd8=;
        b=DJbGZxLONRCTDGjsyl6F2apqZh0cqbgF3gmI69IQcovYht9JUgSmfmlRiHvO9LHuQc
         iCyKdZeQTdtvnq4lKZ/01FM43ZManfG/QN/d8pdg9Jf7AhFJQlDGet6HvMyEwwNtqeZ4
         oyCK78PX6x4Rem5O1bVn/8DfPxpy86F+1Y4Nk/MqPK+/OEmA7/XjNOzcptJWS7H1mvKg
         lVCiW1bgwnIHteQI+UnHimooE4fT7AD48mqH+4VM9xHu+/E2wBHOHgfVlD2Et7IQhTIP
         1ZmF7SEu83Bszi6TyYVwnTSAQ9ivNq3EA1+9iv69XPPdV7qrQKPFhYZNr/ZRWv9kJ64M
         uSCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dOQ7B6H3;
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731006327; x=1731611127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ipRByywzxgKsw0MjdrlYqVsp3r9QwKDANgQew0qyHW8=;
        b=h48XbsTyiIS+4jm87OogCvgHqhJTY+2TD4jIgApa65Xl16EkY7oI/b4KYS5oP7XGzS
         Kso+8u3Zv4nLxgMtnYt4IyW7Gm+jk6nVO9wexbpPNlpqU4cbj+KGCVFaxfmMxvhsydUE
         7z/EuXxXpfa8j88qYOhIpUkuHBgfk4HcjKGM1fcHuHKflaNyYgeuvkE4o/wgHdJ+r0li
         QEW8Qz3Cks8L0qL18ggJaVrcHIxde7sDZbkiqbSc/D/M8WV2PPd4JzU1+RXWNi5FsZvt
         6eej7DA8S8hm7CpNrYKNMSeRYu/+bYZjWrPe/3PREQ9OTYs2OWZVFEZFeeQYtTSDl2Gx
         zVQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731006327; x=1731611127;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ipRByywzxgKsw0MjdrlYqVsp3r9QwKDANgQew0qyHW8=;
        b=OMOTMSk1ZcESuFM3kawvzgXkfUq2YH6QAd6AqhKIrDPDGnFQwOGKSinL93mCyO4TBL
         Z11+7fl56ZF7ayrOa9Y8hO/gVwrUxb9Tpfch8m0+Am5bk94fmYhgRSpjzj/FO//PI0uM
         NXlhTx0c/m5G/p0wq6Z4X9SvkBVFaPxa0EIlNuGSHIShQrzQS5ZvqYwKx+9ji0E+v6f/
         GpVZ0yaaZTDHRIJ/EvD7iZVOZzfWffuvv3NDuN7vwQfVE/vnZnDcRrL9+6972EXBHMC3
         CJUCopvDywneg1lKXPPcUMU/UUJaUnacShlQMDyjjunFlNCRv4NWoKA4Ovi40wCXfPGB
         83Ng==
X-Forwarded-Encrypted: i=2; AJvYcCVhQH3o52i7+ZmJSINTvElkCsFt52VmDobzd7wlBmKIptKPAP/eaiVoFq7agnQJjrfPS4RNxg==@lfdr.de
X-Gm-Message-State: AOJu0YyWTFG0vrChkurilitvENS46a3ptD6Z3I6hYqL8Gvj8Icg34PaL
	JBwy0qSaTjLQ2NJgePVBuxOPldQ6oVsTHOWtvpEq0RtS/pj94dXO
X-Google-Smtp-Source: AGHT+IGzVrMclUuWpPkwiig7vqrg8AhyULkM2yadMTs9IbRt3Fo7xY62XJxdA64Zwafl4PJiqYnbXQ==
X-Received: by 2002:aa7:888e:0:b0:71e:589a:7e3e with SMTP id d2e1a72fcca58-724132791a2mr242718b3a.3.1731006327275;
        Thu, 07 Nov 2024 11:05:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8755:0:b0:71e:6edf:b2ac with SMTP id d2e1a72fcca58-7240340be7als953534b3a.0.-pod-prod-01-us;
 Thu, 07 Nov 2024 11:05:25 -0800 (PST)
X-Received: by 2002:a05:6a20:e613:b0:1d9:fbc:457c with SMTP id adf61e73a8af0-1dc22b5076bmr47528637.36.1731006325674;
        Thu, 07 Nov 2024 11:05:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731006325; cv=none;
        d=google.com; s=arc-20240605;
        b=KyUGDzI4yFs4diqfl5yjVyc+xyk87FGzB7ackMf4JQX6JdiBK4SvsSGP/1y5CbpYFP
         EwfTW9oQYQ8pP0ZR2o997BQmFalpVxGLcQZ//tBnktSO/xaV1Vw19aq2iHtLNeQgPTak
         oBMtASnR6hXUoVISrrZrAwiHOLPUJltj8OjXBV5PbZldtNm/hedtrvpstqm02lJD17Pr
         gLUPdPU8u79xNYKO+UHDqDrlBQj5wHWkWe+0L/ii5u8ymP8bt14TzPwlrnb2kLy/DdPf
         lHylk6rFKHHVO3tGybLdJno6uZ9+zJutFQ9YrgDWPf1CKAwz/OLoK2c0liy4GyDlocnh
         Br0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=KYDCVpqBCC+pX/zhslHT6jMKG6ObK1hTr+grL2OMDWc=;
        fh=tOqXiQFh1MBU1c50ResMmGGq4rksEebGvCbKk5tb3A8=;
        b=JxLkTHKAdsIkh8Sy+jN7qiDR5LNSD5j9g5kvI9uhTZPO0Gsk8U7Z0ANkWFneOcIlO+
         g2pZb7+y0pXcyZnFiju7szmZyu2+e1zAZ2f1EBBPRAiN/vWa3b9jvqXT+IHcyUy4E88Z
         rM0kIPD0siWXXxJPyeOfZEtGE5dEpE+seWiS6JfXv8jf7y6Op8gjyPx/xlbx/dEnjbYH
         2+s0eFN/Ztz6Ym/1ruh5jUJvMT7UVjsj/aEnC5TyRhtGe3VoSh0kpavIcKAgc0Q5viT3
         MuvLfXXdhr9b56g4c0shRx/8BpfMkIZgstmS6M/qwlFmNIrFpBnDaSHHn9MTYry9Q7uJ
         iK7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dOQ7B6H3;
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7f41f67c6d1si100961a12.3.2024.11.07.11.05.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 11:05:25 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 5400B5C107E;
	Thu,  7 Nov 2024 19:04:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A8117C4CECC;
	Thu,  7 Nov 2024 19:05:24 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 50512CE0886; Thu,  7 Nov 2024 11:05:24 -0800 (PST)
Date: Thu, 7 Nov 2024 11:05:24 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Boqun Feng <boqun.feng@gmail.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: Re: [PATCH v2 0/3] scftorture: Avoid kfree from IRQ context.
Message-ID: <b9079817-72bf-4f6f-ad4a-b423a7d2e0b4@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20241107111821.3417762-1-bigeasy@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20241107111821.3417762-1-bigeasy@linutronix.de>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dOQ7B6H3;       spf=pass
 (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Thu, Nov 07, 2024 at 12:13:05PM +0100, Sebastian Andrzej Siewior wrote:
> Hi,
>=20
> Paul reported kfree from IRQ context in scftorture which is noticed by
> lockdep since the recent PROVE_RAW_LOCK_NESTING switch.
>=20
> The last patch in this series adresses the issues, the other things
> happened on the way.

For the series:

Tested-by: Paul E. McKenney <paulmck@kernel.org>

> v1=E2=80=A6v2:
>   - Remove kfree_bulk(). I get more invocations per report without it.
>   - Pass `cpu' to scf_cleanup_free_list in scftorture_invoker() instead
>     of scfp->cpu. The latter is the thread number which can be larger
>     than the number CPUs leading to a crash in such a case. Reported by
>     Boqun Feng.
>   - Clean up the per-CPU lists on module exit. Reported by Boqun Feng.
>=20
> Sebastian
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
9079817-72bf-4f6f-ad4a-b423a7d2e0b4%40paulmck-laptop.
