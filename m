Return-Path: <kasan-dev+bncBDW2JDUY5AORBR5A7PCAMGQENL556AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FAFCB278EB
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 08:14:33 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3b9d41cec2csf1258505f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 23:14:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755238473; cv=pass;
        d=google.com; s=arc-20240605;
        b=capHDKCIAC2biYcfUGdAU7l+dgQMXz00ylk3OZ/RLQhQvgyg9LuF+1G9nxBgMCQVxt
         j7YsO9cxoPGmlwxFrqS9/csHYCB+pAFVg7cvNpc5z0k5x6SaCBpjqGo73wlBD/0ps4LX
         EaGZQty9ZhdUCZTnV3gvx746Lrp2HbtDAswFd8Mi+VVR5j+9GkdU1FdiRrLSv5+Ls3EZ
         VwdtyKKQvOEd6enf0shwTrzHmcRb2IeXpHo4KYf13n7x6HI034KNoLjxqYFNNCQC/6hy
         JfCIYBmK6s+2o9eSUA8+9w6Wd5yVxpDuG0/PWNR2S5Iti1u/KKVzPHRZzLhW0wrqFaQG
         wzvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=7k8wZWtd17JpolWlMWFNkDIBCIp1ztwsAsmaLWyR52w=;
        fh=NOPdXP8PCKkTLtp4tQActSQZN9wQc/pATzVLNlINHuU=;
        b=UcGSt/3j5UFHAwVboREibIbD/VPSCRB7N9KuuyZ/3E9Q92bNHd0oYNljiWekSrVeji
         6knd33W3KxAFzUOdFChNNabaWRO7QcUKgeUhV98XAU93Q5P+UuW0a5Pm7OdqiHS1LhfB
         kVaj+csxAxoxNWemcSOn8eZE9GL0GoPZyA/ecJgf/YUZXixv78OV1hLnRpv/2KPCH0hs
         Zuuk4JYvgCHbRJk7FJpmoJz+5dewmNI/MfQPDwwNdwNirneiw+G7uzOfY3uVw95haIgp
         qcUzIbgDeAzk6q/6riLPWaqLNU3xgBP2KEPyQKIe6WEXw2LLspma92317OJs5JJ5yKPi
         tJ9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VMJspRkf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755238473; x=1755843273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7k8wZWtd17JpolWlMWFNkDIBCIp1ztwsAsmaLWyR52w=;
        b=OGLm9EOKQFY8H1uGCufmwtUKVdSaQdBUDCzBNdYN7qKmowL/UWYIipG/aA9S2WGrF6
         sRtPjVZa2NsnrHoI57j/tf/gi3MLYE4jBTEGDTDliWD3zuTbI8fZFWCrFxWdOZRAtIpE
         ZbOEwMFbbUc0i3gQkTjxfUmDVYJNfolhx14MhqXNj22nBRhdjAvxc7TGnhFD9MDh33xe
         4FCVvAhjOJyFSoduYuUyegRzynIL3uz7qwRQAliAKoUR7vfq6peoB3Kgb2GGk5Ho5sWh
         ExRFIC3JhxdJFcQu12tZZj/uPDarkEIkRw+48XvVR1it5Lk9uaz3YwRBjl0xH5SbLioL
         fwUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755238473; x=1755843273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7k8wZWtd17JpolWlMWFNkDIBCIp1ztwsAsmaLWyR52w=;
        b=mfFniC8V1DrsiyAUhAhdkabws3OaH5AvahEwckT26CSsZfwh/QfPJIRPDjMbtbQs6u
         3/5X6ZMSCg0niMOjAhqyZKHqTPOtmDHatttwmH+Sj81zvyV8MIQ3I5m9+n2SBajOFvKx
         u7/OWk4ZM/+3rtyvfTzJdc6u7xvpSG/kfjGDonidnJ1wajzfWhCybSDhtcM12SehtPtG
         ndfbBIoXBdblM+wMrz+COydOOW+jDE6VohkcKIpPlh2qfyF9K6Tn9jkA0Web1jbxgdX0
         s5gTyCF9pHnxDhbCo8jj61eAIMnViSlxuuVtOiHXtALx20g8YDyijh44/LX5VmV3h90x
         IrHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755238473; x=1755843273;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7k8wZWtd17JpolWlMWFNkDIBCIp1ztwsAsmaLWyR52w=;
        b=of0OVzTufx94sqkIL/lqr5yuE+EBjAjiweVxKIyvqlnJL69DAT/ejL0DUtrP+vTq6q
         Y+3FMrspe3hBvUZ6VbQVv+TznCsK0BfGP9RGwQuVUrKhRP7fRu3O3andrEI9VcGHPmw3
         w0fMbp4CvhjDhktRGpZN6JkUx9xmgmzkQWZCO4iwxff+apJNmHUMrp/WO84jhFteND01
         KH8R++xaJ0JEf4qlSaFVb4fWZIVn7sMCgQc4YrsJvAreUurcgXJYDd6YDOSNJnxkzH0Y
         zCcRr3MR96Rg/lo+9Cq8AJ2InL3X+ERvtjTv4dLfXgO5kCFFvM8d2Av8MeMOPBjztQV3
         r8jw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVDg2OXna0sCMwi5t3XrCQL/g7uiPdHnBgMWZQxc75LlixYmc+eD1AjRzzoxffpbXt5URevGA==@lfdr.de
X-Gm-Message-State: AOJu0YwMOWYasXV2ZTK5RZur0v161+3yz5A8EXjk7uFw/fASE7esVA3P
	OkB0xsVztsGCUBEjgd84Qhd/S/kDUkBfkt5vKf5FvCHCsCfphkJz+FL7
X-Google-Smtp-Source: AGHT+IEl2hNp1kcka1drPHoOkblsgxfq027nk9umrv9yORqCI9n2peAYCAtYDGHftS1zknTPYXfMCA==
X-Received: by 2002:a05:6000:381:b0:3b9:16e9:2cc2 with SMTP id ffacd0b85a97d-3bb66b333f7mr575496f8f.14.1755238472502;
        Thu, 14 Aug 2025 23:14:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZctxTo2Gp/x2ZcysbwGH75Z5PKjmsLrKSF08dxKSNdmDQ==
Received: by 2002:a5d:5f54:0:b0:3b7:7a92:8205 with SMTP id ffacd0b85a97d-3b9c9cb9998ls898709f8f.2.-pod-prod-02-eu;
 Thu, 14 Aug 2025 23:14:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5y2vmooOoyjbpQwBrjOjb3TnoIgtCT2mSul7i/3ZSznTPdz0i6Fs4H/jqjbL1DLqcPJ1i2SgGMO0=@googlegroups.com
X-Received: by 2002:a05:6000:290e:b0:3b7:7d96:e24a with SMTP id ffacd0b85a97d-3bb68a15de0mr555292f8f.35.1755238469532;
        Thu, 14 Aug 2025 23:14:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755238469; cv=none;
        d=google.com; s=arc-20240605;
        b=RFr3hvJCt1tBcYbcxR0CpUU0++FoYd2YD/JSDl2E1owmJjGPcV+WvHUm967mFrePEF
         nwtbV/ARDApkNWCKhOw47yisC3CJ8ASvQRkPUa5MkO/PK+OyWprsk0pAOtycFu7gpqId
         tpOTN0PyVhI5Y72PQHlIVXizIqMIIVZtTC6KMbGcXvHXW+9oy+zAAot+22QY/m2tVVe2
         A4tSpanypyXvuAElBoFz03CSj5IYkGXDCjWo2xVOF4QADQRM7PHvqup1faPvI6PDR9lj
         7koi5AwMHiyohvhdVARvZ4ytub6RJgGH+HT8czPynPjXdz2fg8YhFNva0PmT+V7VS6Dc
         lB1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RC3G8Ydq/hH7/R8jIdeAziyUg1MV8Z+nvGhUkoaFFOw=;
        fh=70ZIjBP/AFtAopN7pKLZcp66/Ugc/7Uwz1dj7/UvKNk=;
        b=Rpcmf/kZVcJ4Zyh6hYdAUo6lNiItgb09XcvOKZz1AwL9tVAdZX76LERvbPQRlACt9q
         HkFOrk1DWeFBpCvi41elVT+FYRM0xU4oYgYbQMVZqx5YiglSC9PutvSiPpBpZWTqGwN0
         zZuK6mwN+Tad+uY2XK3eszGaeQ3aw1DFcEg+ixBocBD0hiYQejAGhXH4hol3QlAHOkCG
         ocLvs6y3zmg966pmlZDSCFYN7aWuc1YxEW6i8xw3iQ7oZ0oPbCsHVYrCCtjWZ32Ses9b
         nV+wVZiMBbiJS0MDSXt2BDIAny74lcBAMZrEvri0oyHrgiLILesHf5D+hHr8PTbFGyHj
         ++og==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VMJspRkf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45a1b1db10dsi1248375e9.0.2025.08.14.23.14.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Aug 2025 23:14:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-3b9dc5cd4cbso1212877f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 14 Aug 2025 23:14:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXSAZZEGdTQkx2c1c17DbF5+CTJaUSPkODZD71GZIRhAOhf1qENetuPEvwCQW7RcgVMhuy/DW6yqLU=@googlegroups.com
X-Gm-Gg: ASbGncsjBojBqjwAeVfyY1eQfxD3x/Np+zlRMu0rRdItNumcgHBwgKGquAymMOHT9L5
	3RWkaIuPPLHMfdiJvv2Q2dJ5MtOQ9HTgqK6a00PZL6gMDEBq95VIHls/hDpJMkfKjDm4+49m3IJ
	gTr0nqFO3iuP+sr/kTxGUC/obu6AHEfsLK+p7KTK/GlvM1sr5ypxBWUnTdw4PGm9X8TIQCK3rKw
	BcYdYhW
X-Received: by 2002:a05:6000:2584:b0:3b7:8a49:eed0 with SMTP id
 ffacd0b85a97d-3bb671f56demr475473f8f.22.1755238468843; Thu, 14 Aug 2025
 23:14:28 -0700 (PDT)
MIME-Version: 1.0
References: <20250813175335.3980268-1-yeoreum.yun@arm.com> <20250813175335.3980268-3-yeoreum.yun@arm.com>
 <CA+fCnZeT2J7W62Ydv0AuDLC13wO-VrH1Q_uqhkZbGLqc4Ktf5g@mail.gmail.com> <aJ3E7u5ENWTjC4ZM@e129823.arm.com>
In-Reply-To: <aJ3E7u5ENWTjC4ZM@e129823.arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 15 Aug 2025 08:14:18 +0200
X-Gm-Features: Ac12FXzA1cRDanNY9nNRCdMRqZ-71xbNZTcaUrUR9hUEP-TJh9C4NEiHu1Mi5Xw
Message-ID: <CA+fCnZdFVxmSBO9WnhwcuwggqxAL-Z2JB4BONWNd0rkfUem1pQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kasan: apply store-only mode in kasan kunit testcases
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com, 
	will@kernel.org, akpm@linux-foundation.org, scott@os.amperecomputing.com, 
	jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org, 
	kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org, 
	oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org, 
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com, 
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VMJspRkf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Aug 14, 2025 at 1:14=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> w=
rote:
>
> > > +/*
> > > + * KUNIT_EXPECT_KASAN_SUCCESS - check that the executed expression d=
oesn't
> > > + * produces a KASAN report; causes a KUnit test failure otherwise.
> >
> > Should be no need for this, the existing functionality already checks
> > that there are no reports outside of KUNIT_EXPECT_KASAN_FAIL().
>
> This is function's purpose is to print failure situtations:
>   - KASAN should reports but no report is found.
>   - KASAN shouldn't report but there report is found.
>
> To print the second error, the "TEMPLATE" macro is added.
> not just checking the no report but to check whether report was
> generated as expected.

There's no need to an explicit wrapper for detecting the second case.
If there's a KASAN report printed outside of
KUNIT_EXPECT_KASAN_FAIL(), either the next KUNIT_EXPECT_KASAN_FAIL()
or kasan_test_exit() will detect this.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdFVxmSBO9WnhwcuwggqxAL-Z2JB4BONWNd0rkfUem1pQ%40mail.gmail.com.
