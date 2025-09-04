Return-Path: <kasan-dev+bncBDP53XW3ZQCBBSPD47CQMGQEL3MMXYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E4C6B44701
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 22:08:43 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id ca18e2360f4ac-88737c85cb9sf148807639f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Sep 2025 13:08:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757016522; cv=pass;
        d=google.com; s=arc-20240605;
        b=FHU2RbRye858zeCv7Bio5wiBCsR4lbv/tVTztuhck0GcieFMCseEB1BsOVEgi9wXx1
         C6kraWsm9f/+Zzezs4CFLRzAgPD70sT5+pLZ3tGME4eHKK5CaP5SUc4dDGPGGV+G6ZXw
         avxe6WfZthHWIu7elPraahsdjxlzyz9ScWQHkhUEQ/L/v/ABuCSodOoUOg2MvjwEgSP+
         On5E6DIVKns9UcCRNC3G+WVTnIjVHxrAUBZy2tQ6hbNfGY9yUZkw+YWe3BAujsZazQ1a
         Z4olWsgsc1ITne87Nh3s9wgPZQIsajdLQSMbf/r2dSbhPEK76uhrSt2/KOMvqdOV3/X9
         4T0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Lm8/vx9ScydQzcUNuklJOeWCOc/Q4QkCC484wr0fO4A=;
        fh=VXc8J+UQpHZB8TcAmpr9EpVYI/ocdLXjkqb333052ro=;
        b=ArDIJiYDtQxaWB3pMJ7LMRT1v6nrvN5cDxaixgO2qGcPt49ImV1ictWp0250/D/sZ1
         waWKv4eDPTMNNOTbQ9GUIw948jFmbusEZEluBlvaGyPZkkspBEmVqjEeXGp84Z8ml3vL
         NcYIkqnPK4p5zNhICtMADSg5T2cJJE8JWtyK4WxaJmundBbGYVVBI6AgBtVDj8zsxvVA
         WOd/I/TnR7nq+f5HBluB+VHlt/KrGelqZlwRU81GfnJf35Z3FP8rJikgFiP8hNzfbHqQ
         PHc7VV1hgjb3hTrAxvt1iBpvxmk/FixIVY1KxNEz8o1yxI5cdrBPN4GTebeop5MRZw9u
         ac7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=StiJ9M2x;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757016522; x=1757621322; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Lm8/vx9ScydQzcUNuklJOeWCOc/Q4QkCC484wr0fO4A=;
        b=ZkuOfUZevi8RUpj5VVVJlZLvsU3PB+XuSUPbgQ0FOrtq/7Wy8wa26GgXiMGBxOj+sf
         +EWl8d/pskqe2ruogt+0prPZRZsiHAE5VI1ceH3cDavcLEoP/LDY/hGhoZlZMbxaRzum
         DNsDCHhkQ8P1SZUY5prEJDib/JxZB2o7jOIcCvgJwV91dy1bg3gr+k8+ddo5t1a8V9xH
         slTtkPMil8xldln+7/bkfi0scU4Srwzp4ltH/Q1tUmKi9GN34nE1jOkJ8uHSrEwOmeQh
         0uM5SWCZtSsdwRC1wFRh5gcpNWnjBqUhh3arsm9+d2SS1/5HOlzd2SfC/17zmsWPA35O
         w9WA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757016522; x=1757621322; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Lm8/vx9ScydQzcUNuklJOeWCOc/Q4QkCC484wr0fO4A=;
        b=Xc7HXH6TMcY0IJ7aGnzdTpB0LCNwxMBNxhB3nZOuSHiBc5W/r/9/intTirstSovrNW
         ex1I9t2eXaMsED52VhIpLLzXljHSNLlMbeyWVq/rvhHzEJelvz6J7nWt0oerF9hli4tO
         HWMHZeODycnTVRvixUUkVx8rwLl7nYNWkojVw6xxp+7HP6cjbh3zgpjyLhA7uxYBgiQW
         6JL3t+9xMigb/MBcV/xWDvtMz6ePzI6oo3eM3LDMFH6PoApc5ILq2xd9ouc7hIk1FDAK
         xxVgRannTCgHZt6tyOknaJG7d4b3iF8DE63gBm5oq2dQKwkX4GQVxCovDqDy9rD0HoBF
         JXNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757016522; x=1757621322;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Lm8/vx9ScydQzcUNuklJOeWCOc/Q4QkCC484wr0fO4A=;
        b=s9DDQPE2B1JmUVQemOcTD4kzqsJ+l8OTtq8hCi+2G5WHoserB/EFWhGENo6Gn11yux
         mSWNLlCrZH0NVClFXQbitQr3XNk22ZIlOl3umusGVagAwqk83xM8XQbyxeG8GpSSL6tm
         pi9IQ5cb21u4uyQ4057H1233wQWOchQVzWo57zC95hLYv6FClWvwIt7UJmLkfWw09Llp
         BIWz9R1/P0ZWEjdyqPHyOz1L+9q+TtJ75kU/PuHakTF+s167wrJzPaTfXRk/0FXxURy/
         IuaZKPUzEbZpQH2nZEICciXfc0qC7QAaJGQvQeJWNXcRrF0zUmPRYltfFad53Ax2YqjV
         jEuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVmDwp7vS7Si7N4EqbCbvYfwoQM8w5AMBG8gXRCqdqPwkB0xEHZHRZVCV6v30DwTAZYIASIIQ==@lfdr.de
X-Gm-Message-State: AOJu0YyLyQ5zsrmNjfnvObEWIp0IQylTkozsukYB2QzXJlNXtfNEL6Z2
	Q6sqOov4xQbxUhG1fR0mB7xdNfvl39sTe8SJ90HXlvVLixLSH1xRxygf
X-Google-Smtp-Source: AGHT+IFq7PdWAS6g++pp1ivSpgdgzi+EF27elvrDTa8lZ1RGsR46roM5qYmvFa7zyHM0YBZjUHt+pQ==
X-Received: by 2002:a05:6e02:480b:b0:3f6:5e2e:b18c with SMTP id e9e14a558f8ab-3f65e2eb918mr143049485ab.32.1757016521716;
        Thu, 04 Sep 2025 13:08:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfrqJi5yNFGxmYJsF4CgZDndzg+EndA5qR289cG4fMBSA==
Received: by 2002:a05:6e02:4712:b0:3e5:842c:aa0a with SMTP id
 e9e14a558f8ab-3f13a5ef32els66936365ab.2.-pod-prod-09-us; Thu, 04 Sep 2025
 13:08:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2az0VJuTqFwZ/v/PPMY6+TXe8h5B6zcDD23eGBdjoeRQSb5SpL/6hAPrABk8GnilcyMOCo6+wBkc=@googlegroups.com
X-Received: by 2002:a05:6602:1403:b0:887:4c36:b3d0 with SMTP id ca18e2360f4ac-8874c36b7dcmr1558018639f.9.1757016520735;
        Thu, 04 Sep 2025 13:08:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757016520; cv=none;
        d=google.com; s=arc-20240605;
        b=GxNPLPZZW2jBLnqybz3iFBLsuFdDJTdGBIxASE/UWtLKVXXm4fbjjsTo1XOB/NkbNt
         VrtgbzHYck6PNO7vWeOWOrD2QJnMXA/WWZHMOQPrZBWI+j0sb2R3AOPeDeGdCfME545z
         WJQ0nNzo0Xm8djOjzpcuWpE6eV2devW4ORH/5sQCyDXoscZNuLo2l0ZviqSDgz7MA7WL
         dgq7uXcxrIy8mjs74HYIa8GcOOIiVfPaibH0Y2cyhp4vo65UoOQv2185fnP5yxbgNQZX
         sePSML82/EtNRuSRE8V8YeSxBodkP7wff67sgB9AzVm2vNxLeO8eusKSlCAne/0Kobky
         JDfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gv63X/vQm384UIbEqWmqDeqv2bYENAIp/s5gNmTAzz0=;
        fh=hWN0Ft8RWLBpgZg9MAatCHJuwjM0evZ7WTAzATIw/uQ=;
        b=h40nX/vF9BKVmLQuuh/ItIhag2aZ6RtNmNNgbGbMpCG95quSzWtuc9ixDR2LkFRA8t
         2yWcgm9fK05pH6TBUfwICoAF5PM5lZ1UQ/QaXtK4OeSB1219HW5Uv3C+9jYG3x2D5mDv
         LzvCWjG/aQ1xd+DhUZWio3bo9LdAZguYoj0MwYMsVfcm6J/icZ3RwxkRuXY5tSYQnW+O
         GBUa3253SX/A8m1Bl1N93VsbNsTSLwaNftMUC8c1ANwXuY3Sy1jIO/CXsYv1O1bIcMAj
         0mcEYD0KLaK54gF5qYG8qVMkBwZj/lsez9Qonz9Txd5JGrVvF1HJ2ore0eD/Slt1NJ5w
         xr7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=StiJ9M2x;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-88762de6471si10298339f.3.2025.09.04.13.08.40
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Sep 2025 13:08:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-b4f9d61e7deso940117a12.2;
        Thu, 04 Sep 2025 13:08:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWe+ppu5APOS+veBgGI88ATzNAtJN5aiko7zziXTk2fyUUn9YetwhLY1tpV796OpuzKO5urYAqByzA=@googlegroups.com, AJvYcCXYIrws6K+uMwwEN4fPcHU69/NDOol8u5YXuQvEyEZQlQqUbXB+vrt8fDL+rYwPKpgJ8g6tKqKDE8QQ@googlegroups.com
X-Gm-Gg: ASbGncuZAMYwTiUc36JaKAS5H0tulKgE8retlRCqiO6B1vI70/muT8q/vA3cqnM/iZm
	Byz4W/z71mh3VNpF93pPvVje/X8Nczr2wItqWAO8GAgvHyJr5cnBJjuDuFHdgLTuDc7qzJh6/ha
	LtpnK+bvBIhk5hzWbzr4CNVZHQo3ApevEnulAe2LnEBqWs0pl1XRRBxH5fob/bQjfJWLfdpLwx6
	GO/NGGsg4YeH8OinKyiRQxqIgjyZbytUya7cA==
X-Received: by 2002:a17:90b:3811:b0:32b:6145:fa63 with SMTP id
 98e67ed59e1d1-32b614601acmr8171223a91.4.1757016519877; Thu, 04 Sep 2025
 13:08:39 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <CABVgOSmZffGSX3f3-+hvberF9VK6_FZYQE_g2jOB7zSMvVuDQw@mail.gmail.com>
In-Reply-To: <CABVgOSmZffGSX3f3-+hvberF9VK6_FZYQE_g2jOB7zSMvVuDQw@mail.gmail.com>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Thu, 4 Sep 2025 22:08:28 +0200
X-Gm-Features: Ac12FXydPL4VUvPU0jz05GoorbNVB63dfkWSac6PClpHYbvI5-ih43lt8hTBuT0
Message-ID: <CANgxf6x2aPfeP8gz6wkKdTZ5q7PDiOYgQDfEYW5Mh37YYTZJ-A@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 0/7] KFuzzTest: a new kernel fuzzing framework
To: David Gow <davidgow@google.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	brendan.higgins@linux.dev, dvyukov@google.com, jannh@google.com, 
	elver@google.com, rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=StiJ9M2x;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Sep 4, 2025 at 11:11=E2=80=AFAM David Gow <davidgow@google.com> wro=
te:
> Thanks, Ethan. I've had a bit of a play around with the
> kfuzztest-bridge tool, and it seems to work pretty well here. I'm
> definitely looking forward to trying out
>
> The only real feature I'd find useful would be to have a
> human-readable way of describing the data (as well as the structure),
> which could be useful when passing around reproducers, and could make
> it possible to hand-craft or adapt cases to work cross-architecture,
> if that's a future goal. But I don't think that it's worth holding up
> an initial version for.

That's a great idea for a future iteration.

> On the subject of architecture support, I don't see anything
> particularly x86_64-specific in here (or at least, nothing that
> couldn't be relatively easily fixed). While I don't think you need to
> support lots of architectures immediately, it'd be nice to use
> architecture-independant things (like the shared
> include/asm-generic/vmlinux.lds.h) where possible. And even if you're

You're absolutely right. I made some modifications locally, and there
seems to be no reason not to add all of the required section
definitions into the /include/asm-generic/vmlinux.lds.h.

> focusing on x86_64, supporting UML -- which is still x86
> under-the-hood, but has its own linker scripts -- would be a nice
> bonus if it's easy. Other things, like supporting 32-bit or big-endian
> setups are nice-to-have, but definitely not worth spending too much
> time on immediately (though if we start using some of the
> formats/features here for KUnit, we'll want to support them).
>
> Finally, while I like the samples and documentation, I think it'd be
> nice to include a working example of using kfuzztest-bridge alongside
> the samples, even if it's something as simple as including a line
> like:
> ./kfuzztest-bridge "some_buffer { ptr[buf] len[buf, u64]}; buf {
> arr[u8, 128] };"  "test_underflow_on_buffer" /dev/urandom

Definitely. I'll be sure to add that into the docs.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6x2aPfeP8gz6wkKdTZ5q7PDiOYgQDfEYW5Mh37YYTZJ-A%40mail.gmail.com.
