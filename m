Return-Path: <kasan-dev+bncBCKLNNXAXYFBBIMB2G6QMGQET5BPNQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id CBCE3A39491
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:11:16 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-439868806bbsf7541485e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:11:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866276; cv=pass;
        d=google.com; s=arc-20240605;
        b=H7Mf2IeYe+lWQT/rNm3tAAbdNkSfr3X81TJSCBTrzSOnAeKzOBaSGTcDACdV8Xg52H
         +xcoX9KNr9UJgQMwMP1S2Nui8yERkuebaChxfIUtWbbiQB/QXTiOoi0YJjyjDlyXabXO
         spd3LdAbBWictAvvIhoEOFH0rNV3DQI/T9kqqAA2qW4t4imHHLyeiMT82+AvtuWSebkI
         lTwDWbmM3OLalf9WLSyhrlvAAdrOVNacqz0xwutIiKqHliAzPs5mQwdIjfLuyJ7wKh9e
         VCzwSNBkUsKff0Ug36YpAHF6j/3juui6R+t7fyZCAnRJd5X0+vcHInNnwOAk5tnWenhP
         +xOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Fh/Ox+86PHBX8Lbx4QIFw/vf04mPop/p6COlqA5mg+E=;
        fh=UIxqmhzaIQ8Pedwu4XVJCBHSF+PN36BlfjP8bZFOgTM=;
        b=T0vaZ6R5FlhTSHPHqo1VWTfUkHa3X+662GQitpI7ouA2zkYK/jY5w0pLUaRp2KG5Cj
         qfQ+3U6zQeLvEWH77VyMvqe0mNMLiGYAiD4wwvKM8xT8I4fWNWvFjjGZ8++62XWaSGo8
         1myXucOoSAf+vbaL8+NBczDIVLcwlw8OqPoGJTYAkGs7JTO/MtrRVj5RB4w+wlPJv7sR
         EAuFxb4Vjk/MUvAbS46VlluRV/gA/Sfza9Ov43j5RFACnoCOCMAEK46Y2htv3UnQJNZk
         TbBJlPVJ+cbOacy31+giV8eIJxgo4peTl1BiJ7kFbVJuE26zFgBHnZ+ljYVBIsx6DXyw
         qjHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=FBPd4RUa;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866276; x=1740471076; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Fh/Ox+86PHBX8Lbx4QIFw/vf04mPop/p6COlqA5mg+E=;
        b=CWIyNd5hjd9pbCH1O31tyoPG2fRrHw5oOIwuXrxwiQQrwn/fKqGY/0eJOh7eb7CU1x
         08A6L2SWMXpWCdbbXwl98m15mJZWlMcysw2gCEZo5Mw2cPEWFRvbLvDcfg0ZIjJW+1Sa
         dMWlunmY7JMbXiG3VSEHMGgIeimD8TiGhpJXjnTLgdLJD5TV2yXOtjlMUZCQ2xqcNPRy
         aH8Doip1VNgidr6SuzT8+j7DQfrZEyzRZbKjAtMYGYwOj3JQjnubSJiWdKVHsXSnM/JV
         EDx+zNTTeNbzMRr1zItynHtE4068cmEY/LGJCqSHo0gpstnKdl9mhNhpA7Dr6SWSX481
         Brlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866276; x=1740471076;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Fh/Ox+86PHBX8Lbx4QIFw/vf04mPop/p6COlqA5mg+E=;
        b=Ma/a0QKBu2YFKUvUMhAJP3B/ufkdC6MLwHCxEuWwliyFGTCxHfUixRUAc3qd5T57P6
         5+Zsb88moPgmb99Oa+vw5Z0g4+S5EQdWMPn6FlxnXg57uaTTOf8z3gToE6dvxaz+PzcV
         +l3Nd3oRUN0RaoddF+tMwcdRurtmbjtzmY8YQgZPTfYGA9rAABnjQmam5+6ADSHt0A9m
         Z4zwDzfyUx/fWE2h4tMxAAt1rAkTEFn+i0qpc0DaudPL0XEajoANLakm+ao1jPu48fek
         6NuElmM79UR1A5i99V0wpfAoBT5vdJg/GTVfBMI6cJrOvfSa0zxRzy6HOrM8QsWrw9Mg
         3UeA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHOzds/AK05nSTWo2Vry65BSTOVWU5dgucZTOpbBL1zBsKKibhpp0oMcr6pzdH4P8BStvytA==@lfdr.de
X-Gm-Message-State: AOJu0Yy4euEcVxP/+tjTuPGhj0TFOQ9CpYfO5jLgKSqK2UBa3JhdOPzB
	XtdV3w6P60A0ExXktxwmBHbXgSUlXjTjYWqqby2tdSbACe6ahCnr
X-Google-Smtp-Source: AGHT+IGVKyqEL2nrPv3hVQt0cIL2ngmiV50iY559WRgJYxrk40nhC/2poy8BRqnYUUwOLS6+/CpApQ==
X-Received: by 2002:a05:600c:4f44:b0:439:9434:4f3b with SMTP id 5b1f17b1804b1-439943450f1mr10180185e9.8.1739866274257;
        Tue, 18 Feb 2025 00:11:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHQ0Sl20HGsnsCkJNr09V4QWtSPM6K3t/ea1ddvtrbRLA==
Received: by 2002:a05:600c:3d18:b0:439:935a:473c with SMTP id
 5b1f17b1804b1-439935a487els1274655e9.1.-pod-prod-00-eu; Tue, 18 Feb 2025
 00:11:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUdc+IbOWk0k7DCDdQWArZejyL77aalJI82kLgXpZFBlT1oejA+bcY8kADT+Lr5nJR9H2GZBHbAnXc=@googlegroups.com
X-Received: by 2002:a05:600c:3592:b0:439:4b23:9e8e with SMTP id 5b1f17b1804b1-4396ec08e22mr109817295e9.3.1739866271579;
        Tue, 18 Feb 2025 00:11:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866271; cv=none;
        d=google.com; s=arc-20240605;
        b=aQxsufVHgBHIYmJ1+B8DQOMyGtRPf+jaz5h1X6LqS7YWWwHTttlkVqVGeGy+8yUY9n
         7iqOdDn1aLasqMRVxB4HrryDQOhbPWnSiWjAYStdVRX2BIPSEQDc8rDqJhJzKYZes2BP
         j9j3f0AqomISUHn2mUl3RFPZddvZlz6yZ9IKMXlXRk01TRG/9VjXQ3w81udVYldBXlX8
         dPOWJhLAotPZpCW86xv69JbNzuAcbHao3tF+eN6J0ZBf71oa7baM4bSggpNo5/rEV39r
         Fs9L0GBu/1OlhB18nB91Cc8LGvQhkLSHkb0htDS2YoYQwyR5Cn82XdvzKwsGbNdJhSwc
         2CSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=sMyD5WghmQkPvsBnt8DB05/niNVQXB+q56W3spPtS8U=;
        fh=EYelCbwDivU5OmAyrzgUNGMGzA8KutW3mLJ1/tSmiKw=;
        b=EnN81zFut5P41IxBqSUI8g7yusb/C6V5HwtxnAnt65OvPgFvumj2uFjszxsWoGy/us
         HNaw5clcyLPxXnT9GwSc83l+EsbfgzER+UR3C66ip28/BZgmGsqEJyAGUPec9eJA5g4/
         tH9ClGDPeSwOyy735X5UUixPP+k2IOQrZKLoSTvw2nxTV/nUbFsx1FdRPdbUcG4hXzUK
         Uxusy3Hul5JnWQn2B98KAMlsP0a1Vg7Bv3E3e3kS58fMmVXtXqq5thMmqBJdRRHaC/2H
         YZVgoaKU38R9Udt68oqsmlg7jOwpU0rhkEL2qgyCI0jy5wq794hWWRHjFuivz6EFYcA8
         6ToA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=FBPd4RUa;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38f2594bb55si142851f8f.8.2025.02.18.00.11.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Feb 2025 00:11:11 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Tue, 18 Feb 2025 09:11:09 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Waiman Long <longman@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Clark Williams <clrkwllms@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	linux-rt-devel@lists.linux.dev, Nico Pache <npache@redhat.com>
Subject: Re: [PATCH v4] kasan: Don't call find_vm_area() in a PREEMPT_RT
 kernel
Message-ID: <20250218081109.Hz-r4tkL@linutronix.de>
References: <20250217204402.60533-1-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250217204402.60533-1-longman@redhat.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=FBPd4RUa;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2025-02-17 15:44:02 [-0500], Waiman Long wrote:
> The following bug report was found when running a PREEMPT_RT debug kernel.

Thank you.

Reviewed-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250218081109.Hz-r4tkL%40linutronix.de.
