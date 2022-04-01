Return-Path: <kasan-dev+bncBDGIV3UHVAGBBZ55TOJAMGQEZSXORUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5004B4EEC1E
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Apr 2022 13:15:52 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 20-20020a05651c009400b002462f08f8d2sf800508ljq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Apr 2022 04:15:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648811752; cv=pass;
        d=google.com; s=arc-20160816;
        b=bjkV4GAmBMuqRGBQZkgVALcGUrp9ANfkglGBBS5XZu9N/T/w/1gLwuLNUvlmr68Vzi
         PX2oPlL3Ey7gRcLcARj53DdI+M1FnOo+BEWFBrGGKQMIe/nmuJrI5zqrJjBt8lIAZtVw
         vxpPhSFk2K0ov3Rvg6+09+ymNBE6VAm68OZkVd51VMum8qtcTZa52u801t396O1elOdR
         k07hfVzwX7diPRN/GaEjvrTXy+LUgJQxuv0cAtP08KgcwuiAqelJc6c3cGv3axlpnf8k
         T/5dYdIACj3oUtjOesvERiV8ITahKxl1ntC5oRCmSNhbCZswx+c1rDgOmUwCC/pMUyHG
         M35g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QlDumb/5mocwY8aRV3PYxNkpaQx5wehh2sP+qpqlCMc=;
        b=VEP0MA8FclN79KGZAAyXfUGQHjbKe6/4x5PLJDfqSSRzkblUFXlONR1j8wyEvbeTLI
         G6sIoVPb2/tMRugWU4fydznZJ7H3ra+TEnb6DGHpaql03QJTd9GeTwMPjHbERyUcXoYZ
         BogT/Y5u2fJU35YV1MOllwhWHRdW/XpeNS3feiMcEmGeG5DHXgZTcAS8gkl+SruYQTfp
         pRY+HyNh1h1Jb8QcndB1yMbbIoQm9NtJDHEucU/2/as+wL46aRDYypOdwFY6pPAEgGGo
         nrDs9XSfykT3NoZUmA2IB1zrbWREDyuYNj8YiGQxhtgXqQnwxd+qbzpcsrNJLIHyvehJ
         GVeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=pjOSccKO;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QlDumb/5mocwY8aRV3PYxNkpaQx5wehh2sP+qpqlCMc=;
        b=khfjohxkGvBQjicmlNdkk3Gci0lsHX/PR/IMVcr+3G12AI1I7uOmYVnD6eRoDVafPT
         uysijh54n2I5r0/56g/z/kIPKyBFxLWQhqPsCrkATqPX4pnkQcnE7i34gpa0vXa07ykM
         0/jjWOwQg6ZvPwPiBVETrdI6/yW8lIparrHFFPqJ5/DmOcrkIaS59Azh3iWSu9Iu7SQ8
         eiasCa3jLDiHoqUgWdqHD/kjn8ETDYFAjbhvXNqUyLhZiA8xDZrZ0ObLLUXoUvRpw27G
         QMloROCEJDwg03xZmkRQ+mBhBxQdSDDCaT0aOAiBpa6c3tb98dF8hp9uA2Qvd6KQZwoR
         mp4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QlDumb/5mocwY8aRV3PYxNkpaQx5wehh2sP+qpqlCMc=;
        b=6L1mfEFRgHgjRdNDfKfiFr5UbuvbWSUoFe90oTFvhEu2pu2AC3TJeP1hY2PsqHAPIp
         ZpnXhYd7qXKYp2MiSP0QyrnqMaGeFau7vGs7xS21upw4c+WxAjVF8pizctcJYIBx4i9K
         zXhHyaQcRqF6NnNKjkHy4hacTsQftjGvtBcoILgZmmqj+Sv5dvtAKzCYoQ5vhvx2qC6W
         E1GofMEGPiF571YQO3+I/KtcdTD/6TTqcXu17ElcNnmHesbu3NzkMiEONk+70WnbmzYK
         Ih0Ob83QVRUMshOvRtVQ9TYX/AHbih+7O9T6AJ1kEF9hH2MtYUOgATvLGKYGIYnId2V8
         hUaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532YcfMEDzJo5w2MD+IIq7tBXgEv8AqeqSxOMmFkSaynqMymnuRv
	1Q3UUcgbhIX9P1CZesQCxRY=
X-Google-Smtp-Source: ABdhPJzOceb+T37Vob/06czXbJjqo1yGsMPVjJWUfG//PxVLOuLwxvII57TpEx9NxEYj25T67Z6eQw==
X-Received: by 2002:a05:6512:ea9:b0:44a:1030:40a with SMTP id bi41-20020a0565120ea900b0044a1030040amr13935695lfb.363.1648811751712;
        Fri, 01 Apr 2022 04:15:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8012:0:b0:249:7cdf:d76 with SMTP id j18-20020a2e8012000000b002497cdf0d76ls315573ljg.7.gmail;
 Fri, 01 Apr 2022 04:15:50 -0700 (PDT)
X-Received: by 2002:a2e:9c7:0:b0:249:81ba:9a4 with SMTP id 190-20020a2e09c7000000b0024981ba09a4mr12999435ljj.270.1648811749995;
        Fri, 01 Apr 2022 04:15:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648811749; cv=none;
        d=google.com; s=arc-20160816;
        b=gsaDqWEQOk9TO2SJi65uM+cKV+7L+H7uTjXnwoaLmvEehPh3oe+QZ1X7yGEgs7Rsr1
         Ea3Bnu6ORFxT+6O5Mv5xHydfAVF++4PokLF2LXklnqYcUiQ2v2mfUWHH+5EZfTsujJyg
         T02xeFKhBi73o4K6gg2nJ/+9iysWDAdVE+GGxPy/FSe2Qzw/ywP0lDDrnvshKIuhQ89L
         haJAVMs+LZvCetziVG8q9G1lnxp/x8S96z6hazhQz4bWQimZGDTBoKI11enumOypmFJI
         TtVJUUI0ATpDXhoA6MPKfwRAKLQNbFK4lCIh/Iq708LNAsBZMqtDMF7okn91lCNgLHSV
         qyaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=oKF9VqRTjJp3lTVoEsc7dqEf9uWuEicp/om5wBdNDCM=;
        b=C+DmW9P02uSp840CTNHdNFES62dx4FV6BaLnPw04FxWaatjfN1chUm0nucBG+R5HAB
         xDBL9wpgtuEXgyZeTziLavX86//Wea6FV4kX/4QJAzGVUAp/o7KxtFtX75EKJtYCkJKp
         uyWrkr5tZRGl39I7kWKSqjShJiN3s25cjYfJLNZmPafiY+RPFu27HRvnjmNj5F2aB1y1
         s/39OH7NJTI5/vitBHnpTtMoimLLuvEq8sxcZxqCU5dSrcCBrRSz5oVsc41bgFWJPYWe
         S+1TDARfIGGhhlB66CxJc8wQYT75y5wfysojfRNLuuZhHy0cneV6koXRJUmemt4SlEf3
         9sRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=pjOSccKO;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id b11-20020a2e894b000000b0024af7c96040si140673ljk.5.2022.04.01.04.15.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Apr 2022 04:15:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 1 Apr 2022 13:15:47 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: "Zhang, Qiang1" <qiang1.zhang@intel.com>
Cc: "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"glider@google.com" <glider@google.com>,
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-rt-users@vger.kernel.org" <linux-rt-users@vger.kernel.org>
Subject: Re: [PATCH] kasan: Fix sleeping function called from invalid context
 in PREEMPT_RT
Message-ID: <Ykbe46hLAfJ8TsnW@linutronix.de>
References: <20220401091006.2100058-1-qiang1.zhang@intel.com>
 <YkbFhgN1jZPTMfnS@linutronix.de>
 <PH0PR11MB58800917A1BF8D1A76BEF84EDAE09@PH0PR11MB5880.namprd11.prod.outlook.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <PH0PR11MB58800917A1BF8D1A76BEF84EDAE09@PH0PR11MB5880.namprd11.prod.outlook.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=pjOSccKO;       dkim=neutral
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

On 2022-04-01 10:10:38 [+0000], Zhang, Qiang1 wrote:
> >Could we fix in a way that we don't involve freeing memory from in-IRQ?
> >This could trigger a lockdep splat if the local-lock in SLUB is acquired from in-IRQ context on !PREEMPT_RT.
> 
> Hi, I  will move qlist_free_all() from IPI context to task context,
> This operation and the next release  members
> in the quarantine pool operate similarly
> 
> I don't know the phenomenon you described. Can you explain it in detail?

If you mean by phenomenon my second sentence then the kernel option
CONFIG_PROVE_RAW_LOCK_NESTING will trigger on !PREEMPT_RT in a code
sequence like
	raw_spin_lock()
	spin_lock();

which is wrong on PREEMPT_RT. So we have a warning on both
configurations.
The call chain in your case will probably not lead to a warning since
there is no raw_spinlock_t involved within the IPI call. We worked on
avoiding memory allocation and freeing from in-IRQ context therefore I
would prefer to have something that works for both and not just ifdef
around the RT-case.

> Thanks
> Zqiang

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ykbe46hLAfJ8TsnW%40linutronix.de.
