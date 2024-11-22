Return-Path: <kasan-dev+bncBDNZPCPEZ4LRB2UOQO5AMGQEUHFDCRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B63EF9D63A8
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 19:03:24 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6d4885111c7sf7240306d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 10:03:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732298603; cv=pass;
        d=google.com; s=arc-20240605;
        b=k5hDDAwzKkGTXz+T2PFNASXTMeqno2/WwI6F0VpQVwpXX269PMZM/AAL7lKQ2cZwKi
         eAVPa17dJCKphXB6jzcte2WOahZtpr5A7Yv7Qq262SEpXeKFJzisvSOL16I2WPmD5sOB
         IIeZsD5Xr9Z95bfeqI8vDpZuvuJAEMQSCSKp+32qic9C1mK43xZqhCE1x6Idi+BajR7p
         VijfRadyPeg4RQR5NBQBDkBjGGpz1MIm9GNL4YBq+n+5jXOifOYSfoBh4HMqR8o7gg3m
         24qez0uVvoXTkPd5szfPbJgcJFXegi8kMje2lHuEyOjh9vNuC9UpUwQzUh4bXX2L3N9z
         oDfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xHu6e0L4+Y4JIh7dVuybWcAcPEHN7Pp6wfCdW/exhes=;
        fh=gLNEfFAx2JXjUnK5NfoWOe1I/u8dqJp9JlYg35evMz8=;
        b=UxT5z0xuWCDGDGGGJqeJhwa2ZRgf/XckX2QgFPlyqceKi9WgSAj4o0rj2e37xQ1ift
         q7l5sn3uMM+8wbxOKqsdSBMQyN+apRZlv+Dy9hN5XDU1AJ7tPkKTz1zHwm0C7+QV6zaF
         +WH5lp6+HDIWSvnzGjMn9Z18Xc3bK0EDGFmQFjk2NPBQmAxzoaewObVt47/Ddt8oRFrh
         uLyv7Iu3NEA3KIBWKmO6uqkIa0o7XSPyj9mDMvngq3mpOH90sFr5NZRhF+bzQchZMYI+
         MkibVGPLM7i2wC+HofO4WM4cTSRwXQ14RB0iiF0HjrZZr0QmcW85Sq43RjCYoW4MteM8
         kERw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dY0y9TGY;
       spf=pass (google.com: domain of jkangas@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=jkangas@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732298603; x=1732903403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:in-reply-to:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xHu6e0L4+Y4JIh7dVuybWcAcPEHN7Pp6wfCdW/exhes=;
        b=PU4UglgQItJudsHUMo9rcTYE3faIXdw7AU42FqrtJx4q0kcseeVFJA2crDYXUo4PcH
         pHgCW7e/9uiERBoEdDackscRkXCxmdcvwLwJc2tMie8aFOtNZrtJrHt/guO/YnQ6VULc
         Im78pmrH1qeAQH6DqXvPUdS9b2hp/CeBBId8/boy5EQ8GOjiB9yJn1aFSJi53sRBsIBu
         aW0HaKec50IzibE4ouEJ5lm5QQVpQ3MmNrwvrf5LT1o+mOCyKR6TY6b93OFVWsx9GK66
         1UCLZXi2XlFkSIHYweBqzBP+1fVBZbLkGo/K5c102GL/p9JRVnCy8e2VcPl3F/Rng9ds
         TxyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732298603; x=1732903403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=xHu6e0L4+Y4JIh7dVuybWcAcPEHN7Pp6wfCdW/exhes=;
        b=vZB1NheOmFMRhrbx+aX2lxWzzJcIXjA9ZK8XziJWOJVrWnKwp6Bq5lMz9da1eUi9He
         GuFZ0HwmiQOWHZ+4pC2rwaoLci17yOaUhWajSD3aCGNSr3Dm6u+70LNkhhACqyDvyfGo
         an3L/8xFSu3YgMBgkH2tOu04i7kvqK4pJV/7fc3c9ciQm3eA6RNUiLgxt1OdxCpI0lfH
         hMQMXQoZEu7thDRmI8k3xys2CMEDIi6CD0d13eD5wtbEhKtwekxeheB1Er5opsak+fnR
         DuR6hYGdcBBYpvovoj12+bVoBqoZD8tfU/Q7NKcv7V+iZZb3MPaGxEapqOq9miXcq9LA
         6NYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfNxWptPCw5/GGrbbA/3YH8AMoaQQGgKK6eKnohYCVM6/hsE0yovONUkWB3Wo73PCaJjMKVg==@lfdr.de
X-Gm-Message-State: AOJu0YyOt6hIsSzYUA1Wibjv2jtE7jrz9WYEUtkt1ovq1s+0HGmEQaS+
	1IDHwmlLi42uQISgbbSu+hnIzgbxFgxEinXpyyxensobS/fOVGZp
X-Google-Smtp-Source: AGHT+IH96PD6kcbKFBvmbrtFYOqjh7ejpiYVdHNdslZX814Woj9y1wbt7Kxj4V68Nlc7pHMmphMsAA==
X-Received: by 2002:a05:6214:2523:b0:6d4:b1b:8b9c with SMTP id 6a1803df08f44-6d450e805a7mr50301466d6.3.1732298603120;
        Fri, 22 Nov 2024 10:03:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:e6a:b0:6cb:be88:c825 with SMTP id
 6a1803df08f44-6d4421c640dls29029766d6.0.-pod-prod-05-us; Fri, 22 Nov 2024
 10:03:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX/TCFyWP+BlY7U+Ad0qB8Rlk70bqd/d7MqU5uKyvuyNuKh+bOVHQNR2VU4PXwFYgKFa5+o4KBF74w=@googlegroups.com
X-Received: by 2002:a05:6102:c51:b0:4ad:4cc5:c33d with SMTP id ada2fe7eead31-4addcedf08amr3796445137.27.1732298602325;
        Fri, 22 Nov 2024 10:03:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732298602; cv=none;
        d=google.com; s=arc-20240605;
        b=LjaAYI2eu8ZLF0HzvaBW0QxMSO/17ZjSxE3uQDDUWq5wRtsncSFJAvx7ezJEMkpvPC
         L+NMCYX1yDuM1Tq7eKc8Hn+PYPDfHy3KmvI4yJ0BPQ2Ct1/SJ+dROMg9hhuloRg4GA6m
         i0KPu7RQi/Sc5njMF0BIOdjSlBaK/jH8357aCoGayUtKzOMBBJLI9fTjseTcADymCNRo
         pH1BEKXoc71mT0ea8FCP4g56iZUHo3S32Fg60eOMuNwflSLeE2xE1kSIDkzEMrR04iz7
         /eYPsD3e59gD4pRewLxzMHa7RnKDKTQcY7hAS0wyzKsMAQ3XsuCzARehWIOsp8ehz1hq
         I88w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=779BNLH2N6tx2iOCEXW0cNJ7EGBdC88+huie7WxmWzY=;
        fh=Lq/tKRdg8QVBJRvt0DAlH7ApBlSVJdquQfPFHm+qj2Q=;
        b=fJ1iDTwVnwYFUknkf583oEsWaxTtBfLj5muM9M9OL7qhFrQlipup/C6o2euor8kXNv
         Y2Pa2F5+JeL1dbmgTyveh/zuedMV8g7hMwASfJH1oi+XU8cDsOKJnZKSRSyhmNBvfMaw
         4crABPV2L6shAShl8Ar5uo9gIR8pyEWK4J2aQr0doqb2DuCsqqDBqZxhSUfkEV0C51TK
         rllUuZkKwBjOzo99RlNcfT3nUjDZz5o+pnbOvtEL4Baipeip+WN77j/b+s69++TgUtgk
         Ls5T133Ez+lSrsKvwMdzHMj/AwcsBnQmx0j+lCdIRBkkndLqYLw1DN+TycbSXqIpOi/n
         sSfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dY0y9TGY;
       spf=pass (google.com: domain of jkangas@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=jkangas@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4adda295f23si143430137.0.2024.11.22.10.03.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Nov 2024 10:03:22 -0800 (PST)
Received-SPF: pass (google.com: domain of jkangas@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-io1-f70.google.com (mail-io1-f70.google.com
 [209.85.166.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-505-BVVrX-5bO46m8-reN_1JpQ-1; Fri, 22 Nov 2024 13:03:20 -0500
X-MC-Unique: BVVrX-5bO46m8-reN_1JpQ-1
X-Mimecast-MFC-AGG-ID: BVVrX-5bO46m8-reN_1JpQ
Received: by mail-io1-f70.google.com with SMTP id ca18e2360f4ac-83ac0354401so257492239f.3
        for <kasan-dev@googlegroups.com>; Fri, 22 Nov 2024 10:03:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUSpLoOgcxJKZkjGRglpaHpssfVt5ratDkHW7xzUw9JNuBqsbdGywc8jHdg3RLfH5yLCjOCpKQ5iT0=@googlegroups.com
X-Gm-Gg: ASbGnctvN8p4l1duJA9mxUoU4O+FQ1z+anJzXpOMSLAC9myKN1BO3RG0BFH4Sp/iKcP
	2+Lv6Y3XwVSQ/ITSOoc2wWWt2nYvYvxg/+TQRwKsmSOLb9b7b01IMgusTtKePgHgdD6XRxkfGdh
	fFR4GDPj+1za7kQARqwPHu2KhKeVBHDQp38YF+0+rnPZqLQVxgbEpHi6sfeiEGO0IKJZSarxsT/
	cEGcm8ZMqrRlkjUjQPBTx0gLa6bBe7EplK4SEvchAIC9adRbKJEV0atKtJFplwZWjO5c/jUNFOl
	7x0CDw==
X-Received: by 2002:a05:6e02:1789:b0:3a7:1c51:f83d with SMTP id e9e14a558f8ab-3a79af1fe69mr43580535ab.18.1732298600052;
        Fri, 22 Nov 2024 10:03:20 -0800 (PST)
X-Received: by 2002:a05:6e02:1789:b0:3a7:1c51:f83d with SMTP id e9e14a558f8ab-3a79af1fe69mr43580205ab.18.1732298599649;
        Fri, 22 Nov 2024 10:03:19 -0800 (PST)
Received: from jkangas-thinkpadp1gen3.rmtuswa.csb ([2601:1c2:4301:5e20:98fe:4ecb:4f14:576b])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4e1cff35be5sm726492173.155.2024.11.22.10.03.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Nov 2024 10:03:19 -0800 (PST)
Date: Fri, 22 Nov 2024 10:03:16 -0800
From: Jared Kangas <jkangas@redhat.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: make report_lock a raw spinlock
Message-ID: <Z0DHZIEI5hobBUwn@jkangas-thinkpadp1gen3.rmtuswa.csb>
References: <20241119210234.1602529-1-jkangas@redhat.com>
 <20241121222809.4b53e070a943e100bb6f7ba0@linux-foundation.org>
MIME-Version: 1.0
In-Reply-To: <20241121222809.4b53e070a943e100bb6f7ba0@linux-foundation.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: gCcvpv2Wzpm6ITGey2I7UjNFoI0UgXnyiDrOktk8lGE_1732298600
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jkangas@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dY0y9TGY;
       spf=pass (google.com: domain of jkangas@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=jkangas@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Thu, Nov 21, 2024 at 10:28:09PM -0800, Andrew Morton wrote:
> On Tue, 19 Nov 2024 13:02:34 -0800 Jared Kangas <jkangas@redhat.com> wrote:
> 
> > If PREEMPT_RT is enabled, report_lock is a sleeping spinlock and must
> > not be locked when IRQs are disabled. However, KASAN reports may be
> > triggered in such contexts. For example:
> > 
> >         char *s = kzalloc(1, GFP_KERNEL);
> >         kfree(s);
> >         local_irq_disable();
> >         char c = *s;  /* KASAN report here leads to spin_lock() */
> >         local_irq_enable();
> > 
> > Make report_spinlock a raw spinlock to prevent rescheduling when
> > PREEMPT_RT is enabled.
> 
> So I assume we want this backported into 6.12.x?

Sorry for missing that; I think a backport of the patch would be
appropriate.

> If so, please help us identify a suitable Fixes: commit.

Fixes: 342a93247e08 ("locking/spinlock: Provide RT variant header: <linux/spinlock_rt.h>")

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z0DHZIEI5hobBUwn%40jkangas-thinkpadp1gen3.rmtuswa.csb.
