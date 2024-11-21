Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLED7W4QMGQEBPKJ56A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id AAD7C9D4E90
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 15:20:30 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e389ef22432sf1824086276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2024 06:20:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732198829; cv=pass;
        d=google.com; s=arc-20240605;
        b=LQhKxK4aD1MbzjULooZT40GlvWkMoLeVAjsBJSfOVU4F9Db0X7Rndbe6IPNOoTRe2W
         lTFaikip1irrKu5ku7O0hR8vVDiK3h0NrbOrLnSb1kLku8j9wly+mRcLvHlePwgWBxx2
         gobve1RuRrAxaKxXaNxAcxRUpnytFKr/XyZNzSmUFyz3I+eY8kjzsropMh5ztMs9q/C7
         i3gKLEV8dioD2GzMptWp/4MeMK8LLCtskFllAmLVHZlHkQqXTIbjncfkAGBhd7LHjrII
         Ne88vB0lv92oqXly+v/h0zHKJHOZpzcAnrQO7tOVkKoj65rk9t8EoiugfGekzPy5aA1r
         3Ogg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DSa3B1OFeccHE9h//SvUpKO/BhxjAmgRsvGuq4p8qf8=;
        fh=KSsI6Og+0svvydOJaov9f7yHJ0rkztz+OBG2MvBN84s=;
        b=YHfOB0mXeqzQEEuhn6vOP1h6N7jw3rx3gJTM5S4q2St/VvzMlxgcjoiYntu4sTAsNf
         wJTOXMZLfuzt8rWwwqAYQGQklGFyGHkPoqrozQhAHzuWEPYvKG0RV74jCOIrNYLo0ROt
         BoyWfiiTdGTC/gIaQnm7McnJ3bUrx7WW3HDWjXTSTTM4/QcyedeBRGSaH7kedihqLgTI
         zzfqZNn6pohZnEspgK/25ZkYqtbSwJIMUIl/dYpPs4lcJVuv1orjZgkNZAqOAa2uigZf
         K4ppdA/2n84lFUWDn5wESYBadGLuvZYpJg073TjuS21a6Yl9hZPgC8lXEOJcfSNzWoQz
         VDSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ePj8EOzH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732198829; x=1732803629; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DSa3B1OFeccHE9h//SvUpKO/BhxjAmgRsvGuq4p8qf8=;
        b=RRESoxvZHJJh17cKLc+OKQ7F66XAiSUSSF0fnig265xaGCJUoydIF/7KpRn0q1/zJg
         jcfSzVIM2+m1He90wR1i/Uj25vQOFWGYogxfzG413WxlWN6uhBMGkV/1I5ICrOu2nggd
         r+/3JuhjFHTnAvk5fTRZe30PdDg+Ik8IbYbOLmxQxhFyzAA4zVRzRe/iCH+sbJiaK/66
         QIKsjhv1MfX2YN3+CGRR7FaE+X8MqGSvnaGnWUTuMR4KjiJDvJZdZJnWQn7WWxNAmzOz
         OhB+6Tk5kY7bRUhr7sVpfMFGRN/05OhKk1M/NZCV9ZjWx7mHwfBFkLziG6o/N7oFyr8H
         Q0Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732198829; x=1732803629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DSa3B1OFeccHE9h//SvUpKO/BhxjAmgRsvGuq4p8qf8=;
        b=gH1ZfJ+YGHdJkyRcMyrXZMlzYFvUl5Q4vJa1wqA6NrmUtEHBtPpUSL2gi69I+FRJiL
         1d20zE98N43OcC/6srrK0bS5nH7qCZ7iYaTR+5xy5LgI09K2TwSO3o/KClt1wk1su2SQ
         wbp0/dGF9Q9RS38hseVjg9W06vBIhfh6m7GOa+PqJtZHLtwyQU14e5ydZ2M18CJnWpHj
         LyhhLDMbLk9LkXq6G9b1XOmpWNNPzyrwixx61giAZiqiAbB0F/iugs5XJWRVPL146YZM
         Y+at1+U/is8r4ojS435BjCiCS4HsjncPLlE0BsiFq4lG45d9bar3B1C3gUqx7pUE93Eb
         ZxnQ==
X-Forwarded-Encrypted: i=2; AJvYcCVNQfCGtCSoCHyRap5jCZ2bAORQdtbzoQu9BJXtwkZXzuclWjALudxHwErM96RGbmF2AQtE+g==@lfdr.de
X-Gm-Message-State: AOJu0YzZE+bYp02gnq7uCwpHzfT5JsOowZlc9qoKRKNDfMiu/8124xf6
	wN/RBzaLkGTiGBX7DdahXCV4PoeIiN5xNPb7azXuvovaG5w0uDrA
X-Google-Smtp-Source: AGHT+IHfmwESo9oast1m7Vu4m4T0pUjZ4nzVhpQk8qmP+XRNbrKcK0EbY4vqTd5aSzlWotrVp90ZVQ==
X-Received: by 2002:a05:6902:c09:b0:e38:131e:e990 with SMTP id 3f1490d57ef6-e38cb60cd8fmr7110399276.32.1732198829061;
        Thu, 21 Nov 2024 06:20:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:941:0:b0:e2e:426f:a681 with SMTP id 3f1490d57ef6-e38e19803a2ls769713276.1.-pod-prod-04-us;
 Thu, 21 Nov 2024 06:20:28 -0800 (PST)
X-Received: by 2002:a05:690c:6d13:b0:6ee:6c7d:4887 with SMTP id 00721157ae682-6eebd15012cmr75266077b3.21.1732198828041;
        Thu, 21 Nov 2024 06:20:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732198828; cv=none;
        d=google.com; s=arc-20240605;
        b=cpaS92ldNUwpo9iPCwq/qaqduUCQs+IyIWR52pNLGXu00aCdkuS4PhoSiy0pA/GY2H
         IlwZufGccnrk4JlKFEG5o34qMiEOZoN6rdOURZs5B/ULvcH8KhwmDNG9w3gmNIhkDbA0
         E5wqZgaxdlR4kP/YTFnMapJBLHPRcJGASGufiTl7kEb51uuPl0VSfhLuX0RxQAH3dYdu
         DcjRp8UuoIjCHUyZAfGsJQZU5hSF3TVY3hNNIs7iXzsaL+rXZ4pd7I4rRVu2XqH+4GB4
         OLW/DUz20sNA/rRdpkMbAC/oaP2/7TlzdFe1gD2mjPW2CQiSWRJKVOHdtuOFYWPqDi03
         y16A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yg61T25n0JyEDgajFQezx7ulax+BxvUMrjfK61A6WP4=;
        fh=RFwShgq0QJL05RiZt0A5CLRXZAsP1H30PcBFDXZjC9k=;
        b=Ns4Qhi2LH1KP/kUMwF/HW02FYNQIuTZ6uE0IkOicggsYDkV8RxzdjN7+LONQa79isj
         RSKSM2d/7MIgmLup3b8xGiT4BE2g/K2MAC4ICM64CN6/4BToZzrDkEgmDvv8vAwjt1Mo
         MKvKJ7dyIiAPCT+hEAfD7aYc/1ailBShfIHrlnThLBcgFJhyCFeOl3Syb8YMCPQTS1LU
         ayDA1musWyoSfOzW8HBf6LxQRb0KrH63vjQ/Ls5L1l4Ot5gYeev9rg5eOxUb7ZMj2twP
         RKGskusrJSVSmUYQDET+VbfcizRb4lqds0nBTusODYVsRkmtcgrVavVZk1U/o3PC2RIo
         9fEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ePj8EOzH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6ee71351848si4008117b3.3.2024.11.21.06.20.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2024 06:20:28 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-724d57a9f7cso403869b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2024 06:20:27 -0800 (PST)
X-Gm-Gg: ASbGnculRlxmi5a3xmPPm4Nzs5VYGdkwo/i0BcNKAeoKx9jZJtEHUtCqAVOapiLHU0O
	74OMUjdyPQMb7Ypn+94NUsfAJyKIAxg/FHtyUDiMFx1RgZRD82ugtlKkDx8pxtA==
X-Received: by 2002:a05:6a00:997:b0:71e:16b3:e5dc with SMTP id
 d2e1a72fcca58-724bed16a4emr8978740b3a.19.1732198827162; Thu, 21 Nov 2024
 06:20:27 -0800 (PST)
MIME-Version: 1.0
References: <20241121141412.107370-1-andriy.shevchenko@linux.intel.com> <Zz9A59XQdiHJ8oLp@smile.fi.intel.com>
In-Reply-To: <Zz9A59XQdiHJ8oLp@smile.fi.intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Nov 2024 15:19:51 +0100
Message-ID: <CANpmjNOQpQdjipRQn-H=noPhDW1pfR--h5hQ+DVXyHTZcKhoJg@mail.gmail.com>
Subject: Re: [PATCH v2 0/2] kcsan: debugs: Refactor allocation code
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ePj8EOzH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42f as
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

On Thu, 21 Nov 2024 at 15:17, Andy Shevchenko
<andriy.shevchenko@linux.intel.com> wrote:
>
> On Thu, Nov 21, 2024 at 04:12:50PM +0200, Andy Shevchenko wrote:
> > Refactor allocation code to be more robust against overflows
> > and shorted in terms of LoCs.
> >
> > In v2:
> > - collected tags (Marco)
> > - added patch 2
>
> Okay, it seems I have to check the Linux Next for the current state of
> affairs...

Right. Please double check this still applies after 59458fa4ddb4
("kcsan: Turn report_filterlist_lock into a raw_spinlock") in latest
mainline (or -next). I had to rework that code to make PREEMPT_RT
happy, and at the same time got rid of all this old code. I suppose a
side-effect was switching over to kmalloc_array() and making it look a
bit cleaner as well.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOQpQdjipRQn-H%3DnoPhDW1pfR--h5hQ%2BDVXyHTZcKhoJg%40mail.gmail.com.
