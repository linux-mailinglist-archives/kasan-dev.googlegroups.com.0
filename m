Return-Path: <kasan-dev+bncBDAZZCVNSYPBBZWW52EAMGQEXEY2XWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 30F853EEC6A
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Aug 2021 14:28:24 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id d20-20020a05620a1414b02903d24f3e6540sf2033513qkj.7
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Aug 2021 05:28:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629203303; cv=pass;
        d=google.com; s=arc-20160816;
        b=dLL9WIunfBShyRyzx/9igAEjVnuUA7GorNxbrvwn25N39slyekLKTUBQwdCVgn9nS9
         Tw1iH8c0SNjAozgaWzH+dgprOltqtuVKIy5X7iiHT8rDD4SpNf7BwDBI4/gXXtMqAmVq
         T+OApP00WB+1M2Af3DAxkjj9BU06WC968qLOiscuWNgU5nm/cX6m+hjuZ/bqKsSySkaF
         afQ9HQtajIKv4QtI2GrYSChU/ojOhtZkfoOR8dZzQ329hm23sqp4+N+dZUARckRJXaWd
         v762D/EKc1S6q7wESAuT/JnFl72Sko6z1pq9crOEUbQmFdns05+B6PIR5jq6MhTLVBCa
         bpRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=p3+KFuU50LCo2h8+RcodmVR6xxxkw9hIUJZr+sBE+WU=;
        b=0O9znqHzr5QaKahQ3Oo3QHVc9cTO1jessA1OapYsty1bLtF/uAIs4RFR+q+lV+qC5I
         XXuT0osUxCRsEeA6uAnYVIuysgRSc2yZHGmc63r7blSCf3N0Oc5bkkt4rmc7nIryikEw
         CG2kNwmaADxccagZTowkqZqXszAhZ7MYFHgeDJEw80Ug1TfNvXAJzro1qnvoszwDgEoN
         8lhs4rbBd6yET4nKJIV9upDpTXoPBLanm+tdHujMHjLLGyG9T9ygrYTYlfmuSY6fkf6r
         Uyx77ViSo5fJcyhMMO189bo/hZGqBOWdyqOAFb5ObjKsGThknXAeuwuATlxJjPaHuWsi
         vbqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fZN234Tl;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p3+KFuU50LCo2h8+RcodmVR6xxxkw9hIUJZr+sBE+WU=;
        b=IqJr1oSuEjuo5zVhfn4Av4aP1dnzACnvqIeHmaHPwniAtOGjJjuT8N0VzJaCgAkdKd
         50gIjMmCTIPC2iEYbKMeAFSfZcpiCD/8Wkycry+o1A4WNuXChwO6HtmowDfvteHeTnir
         jhQmjfzCH4ZFSwRgag55H2+i0whv+Kp/Enq2HY08vYJrX79+Pdm7cql7XNhGLjQFZ/Lv
         m3zMVZ2KBt5Eso1IGPGYAplIlvwYCS5TicxN30304ERj0fjtzLIQ37hAgfZHi3ARNbrG
         lQjLFIJgm6hmA6Z7seDS7BLmznRQ2u7Da95RQYNYRoWjyAgovnGoEgD/XZI+/9GRJIo2
         i+7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=p3+KFuU50LCo2h8+RcodmVR6xxxkw9hIUJZr+sBE+WU=;
        b=LhbNePD8tauCw7PLQKM1XNNPHUJraqiWzGDQBsaprzLb5yorcZ++CTQs387w88R0Z2
         blNWEMRtJa2nJUzvc7HdF2KpOD6KMRfL6Tcopj80T9w3ZUXzGq80LFpS3LA09fuds6+0
         4lAmhS2DJuHrJxGxzbct630kLTynBysImasf/Se4KGEusm44ukmRUgFv7o+pwB1TjpOW
         hopaZR1uA/IpgH4MVqKb7fXnH2ALr4rYJGhJC1eCM0i4ozGZA9Nbd2WAQGB9FunTCuxa
         s8guNB/YHHU5OoAyNIoFugXnD38HPOSy6K1N89z8E6bkuHVXxvMRamZpRzx8DXYXqdEW
         s5aQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gi+TRIXcAhv75enRuLjHKzYadCTd0+Ae6gxCzvzmVR1aE51Eu
	gSlZzgr9XC8UZSUV3qjE8Pg=
X-Google-Smtp-Source: ABdhPJxZhnITuu26S7gg3YRW9F2pID8KTIhoCH9dmDYMvPaJvwpiackqcSmFBXKbL8GXpikGsMkdRw==
X-Received: by 2002:a05:6214:23cc:: with SMTP id hr12mr3046933qvb.56.1629203303067;
        Tue, 17 Aug 2021 05:28:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2699:: with SMTP id c25ls1454879qkp.0.gmail; Tue,
 17 Aug 2021 05:28:22 -0700 (PDT)
X-Received: by 2002:a37:9307:: with SMTP id v7mr3436731qkd.371.1629203302661;
        Tue, 17 Aug 2021 05:28:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629203302; cv=none;
        d=google.com; s=arc-20160816;
        b=KfZ9frbh1AQTguoeW1jHw6Lx9RR+JSOdn03IzGxnRUjq7BsY1SG700cYSeK8fs0qTC
         nAQPGRV6jrds4m9xt9E2KIKzSaqQpCJN7bZ3FQhM6xJnsF4+FlLH4H36NolF/DEmZJ4B
         AfoJGq/pmKVBZFjGO7ND6i8S5JYESNYUi10ZIToy9P1yHZCepPcYzEOVIEeDHzGOO2gk
         8FUgiIQ+KhZYSM2nFoEtsgeB59TEmLBKwp5wa/6Qa8mxjq/EV0eZFxDSVV8xDP5Qms9B
         xTl6pes+JDbUp3oKLgcggcQluSsw3nHbUtc+gecKWEQLF9N6o8voO8gLjg64zLKnsvFJ
         Z2ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Pk7nKUdCu65etUSdtEDAenGNgDdWFI1+4bhQH0/IknA=;
        b=lT9gl6O5qFPTE0Ui38fwmNINBaKGOB9mroRRk0hcn+thpNQIFKAlgyKGe+TrjdTG17
         HUoP4EZ9F90dVEseViNRWmbROv5yxaG96U+V8QUJz87XNwvuQjUdZDlqGY//mVVGVvZy
         DghPReZ7zexHKjgD4ZFaTaRGtaFY44XblRWgL3MBAdg13yj2HJQKwDkTSDuZFxImTza+
         iMlI7rCWz8pP26MgY6xpaUImflxl1irhBte2PoGtMwIPj/bapuXemWxeMnC0pnapY28s
         ky97tkVPwhCfrYgoLVIi3qpUOUPQDZzBJK7toAT7MjC/yNac0gOmr7jjYa3TV+Weo3Tk
         l/Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fZN234Tl;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 10si111765qtr.1.2021.08.17.05.28.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Aug 2021 05:28:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1911B6023F;
	Tue, 17 Aug 2021 12:28:19 +0000 (UTC)
Date: Tue, 17 Aug 2021 13:28:16 +0100
From: Will Deacon <will@kernel.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alan Stern <stern@rowland.harvard.edu>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <20210817122816.GA12746@willie-the-truck>
References: <YRo58c+JGOvec7tc@elver.google.com>
 <20210816145945.GB121345@rowland.harvard.edu>
 <YRqfJz/lpUaZpxq7@elver.google.com>
 <20210816192109.GC121345@rowland.harvard.edu>
 <20210816205057.GN4126399@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210816205057.GN4126399@paulmck-ThinkPad-P17-Gen-1>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fZN234Tl;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Just on this bit...

On Mon, Aug 16, 2021 at 01:50:57PM -0700, Paul E. McKenney wrote:
> 5.	The dma_mb(), dma_rmb(), and dma_wmb() appear to be specific
> 	to ARMv8.

These are useful on other architectures too! IIRC, they were added by x86 in
the first place. They're designed to be used with dma_alloc_coherent()
allocations where you're sharing something like a ring buffer with a device
and they guarantee accesses won't be reordered before they become visible
to the device. They _also_ provide the same ordering to other CPUs.

I gave a talk at LPC about some of this, which might help (or might make
things worse...):

https://www.youtube.com/watch?v=i6DayghhA8Q

Ignore the bits about mmiowb() as we got rid of that.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210817122816.GA12746%40willie-the-truck.
