Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCHWSO4AMGQEWDHJI2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 43BCF994436
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 11:27:38 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5398f3d3757sf4705071e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 02:27:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728379657; cv=pass;
        d=google.com; s=arc-20240605;
        b=DOVM6M46ymRmYD2W72NWJupoh3DTd5UMnij2ZjFX9MoVoKcdAvLg95j06Sel7S7gLY
         TR65bHJzg0TZXb15FuqCJFKcTp8aKH0pVZIcskQAyKLP2RKnOXLdPBf6wJAnu3oNVjs4
         wWSuOT9H4fmA4euiD6i5VBle6zghUZVRmDtvEYOWmUETEBvuAUL7tj3BNornmt4t8ieG
         I0eMwrGvELgOqQS4hV4Uw7EGsgcc5+r3i/zVykR7eWhoi+RlPphfkY7oXyRnlsHJcIIC
         MsK+JWc3qDnffry4Oo9XtQkOX8Jyp7PpuPl80qAQd7RvVBaTadTAzcscHISi2npBgKDu
         mkng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=J0k+V1tUkjfOHKR7RLf+4qObip7wligOi414SFsD0Os=;
        fh=JbFmwek8By29lziGqiw/BAwduzJ/5EwaA9pnthweioM=;
        b=YoPYYVERmtSADr3N5W0CgnNHiL6b1EEoS/rSEuizBRm/jP/W8qtQ2YpKCV7e6y+ekE
         AO+JUcbCwvKoBQ6p+8whv8LaDtSBLwTs5IMvo6gX2q6nfegM4mK24Y4tUnccPcFHhsk6
         ZhvZ2sdr10EROTRtoT67/Lzc6RXYWjyO1oSaxr/4U2P29508OYA5M5COsYV8l90+g5wI
         VxKnDaR/iBLvE3kEKSEgDByNb0r88b7DLiUNAwZ7/8AOSo7+Xu5NDcDuIWPxeT8jOvdr
         fMPTiKbCr9NbuA8Yxf4H7osHViflIi3V9+ntOO+ocqJsI8uo0yCYf3QzoFOE0qq3YyRh
         DbCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4vRY8jNE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728379657; x=1728984457; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=J0k+V1tUkjfOHKR7RLf+4qObip7wligOi414SFsD0Os=;
        b=uCR/Kh+KyVk4Ch/2OoClw3+b+KlsxoHLgQZIGKkIYnTcqT16mD1Ckd6RTo58IWvIMb
         coBx2ERsoibmOSAdJ/jYnGo5ed/Aqi3+86C/zbXZZfYhhepgGdAr1ToGVpBiVtGnpCzD
         ibjS23kMX4B7Lh64i0dSDFu20DvFsTzbszyS6JZ99F62m76olh9HUqCpTajfv7msloB2
         LSTMV+OGzeWi60BKx4tO1n9Sluykxpay/f2h/ZLDDDahn/+7cWrVfhqoN+pEivut4Z+h
         eYj9LGQCSQjDsdKvFLIrPkS6yVSorA3ssdmLd91ildOtFMBRJoWTafV235pGmE1BHNd+
         3sbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728379657; x=1728984457;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J0k+V1tUkjfOHKR7RLf+4qObip7wligOi414SFsD0Os=;
        b=cXRCaHb/ij080g9PI+T2SOsAvFmhPYArl3upVly8TY3ymQVWxfQp8ar+0DjsE5gLNQ
         b0atOM4qlBfiwk4XCIm+d7bmIxzyw3pSIVFvTUU7tQnRIRdMa8kteHuBlTzOkoirmzXx
         eOPJJOREcW2aq+paFtZ873dNod2CivGd0dm+qerCS70MMirmecM/tkiVy1Yg2TRhO7va
         8jz2a0QQR0BB0yzF9nJqS8cieqpBDJfcuZrk4Wz+IFdg+I5Qslif3S4KDWdSDNV+9Lqz
         qgz5Oll1149v5wtZyby1FIpJwkTvNHcmjrLQFjVPdK6bojInDdls5tm1dgRbRBCGSmwn
         K7kQ==
X-Forwarded-Encrypted: i=2; AJvYcCVOzhBeR9npTiZvQ/0ghuS48GDCQAEJJzgMSViM0CUl2r+RcRoamgEriEdDMdYPLtGys/qdJg==@lfdr.de
X-Gm-Message-State: AOJu0YwWotIVDlEts3pA6zPvILKGeIXHXV8PEbbPG1bcxHrag0Vmd3Hg
	vLYaP13r7JZYFVDaKMJqqWa/jmhlNm5GHVQYN7ZXh9GKVzQho58d
X-Google-Smtp-Source: AGHT+IE4Qr8dZVpH/b8QaZguXZ8KFOPIbZn0ad9AQpKhVb/BWOecADOw4sZaji+bCMZA4q78GjUxlA==
X-Received: by 2002:a05:6512:2245:b0:539:a3cd:97ca with SMTP id 2adb3069b0e04-539ab89d887mr7369304e87.36.1728379656744;
        Tue, 08 Oct 2024 02:27:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ac8:b0:539:8f61:772d with SMTP id
 2adb3069b0e04-539a632342als412858e87.0.-pod-prod-09-eu; Tue, 08 Oct 2024
 02:27:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVM4KEXlCQRjLA6bRwSfAlRgnoRsbNgXZ6JPv2gLokVMwSj/GXH9iR/JvCLeXBhzB061AFw1MLzbBw=@googlegroups.com
X-Received: by 2002:a05:6512:6ca:b0:52f:c148:f5e4 with SMTP id 2adb3069b0e04-539ab877e7cmr7913280e87.21.1728379654202;
        Tue, 08 Oct 2024 02:27:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728379654; cv=none;
        d=google.com; s=arc-20240605;
        b=dT3POWNoOGBpy2QfhAYGX72a4FBbY9YkmloXBBDnYUxSqcfLK2U49OmZo3p4BnX4Tv
         FsIAKpl38xmHQeIDxZDWFFUc2diXaN1yQIwcceIY6Bis/DkIPedPW+Gkk9w75sVvwgKi
         oq+v8QuQ22mnRQKtKNPJu7n9gthmlgDuQjimFE420XwrUqIF4pu02gnqSLfDCsGVIDVt
         w15Sq7LWqPUkwiLtLyNC49Y+mnwoDFmXxIkPVpV5XZVjPWPD38qq1sgnUOzSe5T0GPMf
         fJdw6A4GibvxLT+iwDEwBSCvYoG6Dr1IPAe7Z1KOERcYP5QSxUSNEu8fZty48I8/Ggd/
         U28Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Ftu5SMGfw++3h3QWzAJcU0tvoV223zfvN8/LiEMFNTQ=;
        fh=JqvC8hBOIqv80YdRiXgGbtoe4wqh0vumxXFIIJ9X03o=;
        b=jXrko4OvzLkyN6P9QFIpAe3w+5V4b2MfYK/r7TequWcBgs9p9qKuSf/CrHf1Rr8kEW
         Ik+LOqNWZWft+flsXOqhTdQorcbNtiblD+aSFuFvfC1TJA+neltmw4BP2YMP+7N8Q8XC
         U09tYA0B5xfr8B/FbYq6ZCosDI9v8/qYQIDhjqC3QPE4symQ6ahqr7HFglAXNxt9Qu8Q
         lsUP2QcVWkdw6fi3C/RwV8iFwpU1wy77/ITX+12wExlWi7UnzwMJGJPnZ+jIzgzdYbwG
         sqKpEnFU18fPKkK2gPFulcK9+YgrgtVESwiKSmJHc3DKVbiQ/sug3m0t8swW+Spf1G+0
         HlXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4vRY8jNE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539aff2583bsi168425e87.11.2024.10.08.02.27.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 02:27:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-42cae4eb026so55967095e9.0
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 02:27:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWs8W3fsPmWfs7GmYWv0MZ3+dmkWMO+UD5pvAOC5OWiIQH8I6V0caFUX5NlrZWA4LuBK08GngOR8RU=@googlegroups.com
X-Received: by 2002:a05:600c:1907:b0:42c:af2a:dcf4 with SMTP id 5b1f17b1804b1-42f85ae8ee5mr101095455e9.27.1728379653199;
        Tue, 08 Oct 2024 02:27:33 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:c862:2d9d:4fdd:3ea5])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42f9384f63dsm43016745e9.26.2024.10.08.02.27.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Oct 2024 02:27:32 -0700 (PDT)
Date: Tue, 8 Oct 2024 11:27:26 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, bpf@vger.kernel.org,
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com,
	vincenzo.frascino@arm.com
Subject: Re: [PATCH v2 1/1] mm, kasan, kmsan: copy_from/to_kernel_nofault
Message-ID: <ZwT6_gzV2evijOGK@elver.google.com>
References: <CANpmjNOZ4N5mhqWGvEU9zGBxj+jqhG3Q_eM1AbHp0cbSF=HqFw@mail.gmail.com>
 <20241005164813.2475778-1-snovitoll@gmail.com>
 <20241005164813.2475778-2-snovitoll@gmail.com>
 <ZwTt-Sq5bsovQI5X@elver.google.com>
 <CACzwLxh1yWXQZ4LAO3gFMjK8KPDFfNOR6wqWhtXyucJ0+YXurw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CACzwLxh1yWXQZ4LAO3gFMjK8KPDFfNOR6wqWhtXyucJ0+YXurw@mail.gmail.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4vRY8jNE;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Tue, Oct 08, 2024 at 01:46PM +0500, Sabyrzhan Tasbolatov wrote:
> On Tue, Oct 8, 2024 at 1:32=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
> >
> > On Sat, Oct 05, 2024 at 09:48PM +0500, Sabyrzhan Tasbolatov wrote:
> > > Instrument copy_from_kernel_nofault() with KMSAN for uninitialized ke=
rnel
> > > memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
> > > the memory corruption.
> > >
> > > syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> > > KASAN report via kasan_check_range() which is not the expected behavi=
our
> > > as copy_from_kernel_nofault() is meant to be a non-faulting helper.
> > >
> > > Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check =
in
> > > copy_from_kernel_nofault() with KMSAN detection of copying uninitilai=
zed
> > > kernel memory. In copy_to_kernel_nofault() we can retain
> > > instrument_write() for the memory corruption instrumentation but befo=
re
> > > pagefault_disable().
> >
> > I don't understand why it has to be before the whole copy i.e. before
> > pagefault_disable()?
> >
>=20
> I was unsure about this decision as well - I should've waited for your re=
sponse
> before sending the PATCH when I was asking for clarification. Sorry
> for the confusion,
> I thought that what you meant as the instrumentation was already done aft=
er
> pagefault_disable().

I just did some digging and there is some existing instrumentation, but
not for what we want.  The accesses in the loop on x86 do this:

copy_to_kernel_nofault:

	#define __put_kernel_nofault(dst, src, type, err_label)			\
		__put_user_size(*((type *)(src)), (__force type __user *)(dst),	\
				sizeof(type), err_label)


and __put_user_size:

	#define __put_user_size(x, ptr, size, label)				\
	do {									\
		__typeof__(*(ptr)) __x =3D (x); /* eval x once */			\
		__typeof__(ptr) __ptr =3D (ptr); /* eval ptr once */		\
		__chk_user_ptr(__ptr);						\
		switch (size) {							\
		case 1:								\
			__put_user_goto(__x, __ptr, "b", "iq", label);		\
			break;							\
		case 2:								\
			__put_user_goto(__x, __ptr, "w", "ir", label);		\
			break;							\
		case 4:								\
			__put_user_goto(__x, __ptr, "l", "ir", label);		\
			break;							\
		case 8:								\
			__put_user_goto_u64(__x, __ptr, label);			\
			break;							\
		default:							\
			__put_user_bad();					\
		}								\
		instrument_put_user(__x, __ptr, size);				\
	} while (0)


which already has an instrument_put_user, which expands to this:

	#define instrument_put_user(from, ptr, size)			\
	({								\
		kmsan_copy_to_user(ptr, &from, sizeof(from), 0);	\
	})

So this is already instrumented for KMSAN, to check no uninitialized
memory is accessed - but that's only useful if copying to user space.
__put_kernel_nofault is "abusing" the same helper to copy to the kernel,
so adding explicit instrumentation as proposed still makes sense.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZwT6_gzV2evijOGK%40elver.google.com.
