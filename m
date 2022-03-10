Return-Path: <kasan-dev+bncBCA2BG6MWAHBBYPDU2IQMGQECUYZ7RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2338A4D4232
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 09:08:02 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id f14-20020adfc98e000000b001e8593b40b0sf1395261wrh.14
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 00:08:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646899682; cv=pass;
        d=google.com; s=arc-20160816;
        b=lXg5wib/Uh3oe6tCoVlGFcvq8niWml26YbRXyTNLuXIrgriBVkHOw5qN/pb5r4U9Eb
         o9zt7A8mdcHQ/WwLtLEg9a0SKmXkGC2AvdxJyFEunGCzy1QcjGVdFIpdnHPaHHHD580K
         704PVFtBt1ONw5IBI+DC53vtNPhPCv6UQXYSZ2Z+ndlaAsvvso20O4iRwM9bXy/EC807
         dnLNLoE2nquL/Ta7Uamg39XV6xDtFAKCKqj2iKlacITq2MdkhmxjXl2kpf9kWHMSUPSX
         GTTWNq2AoT41FHXNksot5MZX7HyYwvXuHKhZ/Fn1yEz/npmtbxAgQBYlJ2HQAL+65chm
         gznA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VAGIC6X1i1H+wUjcu0edarYaqtOe4zzbcWsfBbCCxsI=;
        b=nrIUa3ZZxOvvs/v2ncLPL70XiYuQO/OZAdhNKnHVvHQUXIOnaTyBNSSZijdpz8g/gN
         VKy9htBObXLhQdwzBhoKKQS/Il3wrvclGajfrCnhj0InL/OeFEmOxn1K130QnEh4ogPQ
         1jEwmEv6/C/b5v28Lh4PyBGCRjNj8kZfpGecdtK8M2SD6KIFv4CXQMGAjAM6/01kT0s+
         CCDlMMXHzIs3Gtp18lecp+YCpmOco1Y6UiHKYYJQOUzkiZ77i+ahBzjC6eb0pL/obOSE
         pojCfkriOfQqKk447M1bovfL8q+FSn6uPYMiaXJFO2uKeXE4Jjj0Q7ILJjHbc5Xbvo+a
         e+VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XLRUu4GL;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VAGIC6X1i1H+wUjcu0edarYaqtOe4zzbcWsfBbCCxsI=;
        b=opW28fIfzIsO47b47LuVDKDZH6mBi4SGL2VDxOELxBk8cOsg/ykGXD21FNWkLgXjOC
         VrX5+Q1UOchQtbnUMKb411JhZtTyzAr1njE9frsp794hpf7U2obC0Apq7ThfYfYt5nY8
         yNgQyXuOZSbVxYDlnKJ82JcEHoFTHfsv7jCqmO2VT/TrJfKVvDdKPWvej1XMK2XNog2n
         KlFIlKeuQ6F5lBD1HHGdkE11VdFa82M6Fh+MExWv3Pjo4WM5SnIdvUa9OGomsw4IES/0
         aZ1tzddSsNxT0b3TDRf9EeaPj/t7VMBou3/Yu7p8P7uUAwIoWGiiHShgaBQepHt59usa
         +M+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VAGIC6X1i1H+wUjcu0edarYaqtOe4zzbcWsfBbCCxsI=;
        b=1r5JzFmKnHpl8v5RXMxVK8QV4xwkdycU/RT8AXuAKvbpr2dmtIW6BNCS4G/l6/GbOb
         M/bMa/6b5fxPZzAffUprTb5p0sThlg6c0TZiu5fR84qww3jwd91Tch/4pBc5ARu9O3JS
         KIF7wN8uvQujWb3bbAdGXT7JQfPSt5/uNOvREbrYKeChrYsBjbunOp96SwhIPHAzFxi9
         eiAlHz2Ev0ITP9OSBi+eqOtQN+jVoY0Q2sKEiNgonHNYyOK3+bpV1zjnfe8hU+ZpXB36
         Bcwk0GBkdE3XmtCBMLYvxlcBvJtivgmWBNDbmsuUEJw6E4y1S11uxRtVKII+wDWqjG5C
         J+FQ==
X-Gm-Message-State: AOAM530n6CuTq2PTjl6Vx4RT89bC11panmT4M72Ef/Xwuu1OIj7OMZ3e
	r5K072lvAuAyK3KB3sjiOyw=
X-Google-Smtp-Source: ABdhPJwCZD2f6roBiOMOUOgpwA5qoROzTbQrN/ZmthmVtEdp6dFJfNvjx+w32pYCmlSGX7UWFYP8Iw==
X-Received: by 2002:adf:e289:0:b0:1e3:14ad:75fe with SMTP id v9-20020adfe289000000b001e314ad75femr2549089wri.685.1646899681752;
        Thu, 10 Mar 2022 00:08:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d0c5:0:b0:1f0:7735:e337 with SMTP id z5-20020adfd0c5000000b001f07735e337ls250119wrh.1.gmail;
 Thu, 10 Mar 2022 00:08:00 -0800 (PST)
X-Received: by 2002:a5d:424e:0:b0:1f0:3430:ffc8 with SMTP id s14-20020a5d424e000000b001f03430ffc8mr2440289wrr.672.1646899680917;
        Thu, 10 Mar 2022 00:08:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646899680; cv=none;
        d=google.com; s=arc-20160816;
        b=Xed3D2F3vSEbucRTVns5XwBye7yD2SHaSE8gPUQUMD5vkRB0CochdNdUDm9wNw3F2+
         p6UMeGgktHO0b5Ma4fkxy9u7QWDRDVm235bCWAp4EsUw7PHa6UJ1GBt+MBzJ3gpVtBQj
         OdaL0EEbttk+4S1ygI55YhZjYqbPRAoDQ7+7QLVUtmzAAR5N6RsgpV26WO2qxHQA2O78
         yuAPGNEH+4vJTNKUtRWktpRhV/68QH1r/s/BkUzTeM1X7q+1Ge5j+FybgSFPj9jxMP4u
         68jhzxPBBrruktLFvizfqPdkq5TeT48n2Tu6NUNZixKftOFNr4y1TdkQ1O7kS3QhZnBt
         bw2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qgU1YiosBtNsX8vphzejZ6JG2mH1MwmM6we31LMy0vU=;
        b=vzKxVE5T+T9IEz+Qzi0a3+pqRJ+XuiKZLZ8rLvR45QdoN4wkSCIa4ACXul2cokNzu0
         XqTAvwBMOviqMWa1PeJDDlmPim2GbAhJz92rEElrx8nosOLKHT0nZ34SVRGmXzP/yavY
         4MZDX2VJVNWc0WolYRuZYk8aDoWHaExXMSoOEdefoejVYv0ezWUG6doiXoHlbzy+VyWv
         FkevgMtlwFnk8kAMzx1o0K1okUrYFuspAeToRFHXN1vGA8Gnktv+HaMq4bjh18i7eLmh
         EXVnggCnsKSP18JiJcjg+g0/poEJsg65ekMYpwcz3viW/3yK6Unvc1D9dTTnDl0M3pcj
         v/YQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XLRUu4GL;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id i5-20020a1c3b05000000b00382a5d09c0fsi522265wma.0.2022.03.10.00.08.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Mar 2022 00:08:00 -0800 (PST)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id dr20so10229021ejc.6
        for <kasan-dev@googlegroups.com>; Thu, 10 Mar 2022 00:08:00 -0800 (PST)
X-Received: by 2002:a17:906:2899:b0:6d6:e479:1fe2 with SMTP id
 o25-20020a170906289900b006d6e4791fe2mr3149308ejd.394.1646899680427; Thu, 10
 Mar 2022 00:08:00 -0800 (PST)
MIME-Version: 1.0
References: <20220309083753.1561921-1-liupeng256@huawei.com>
In-Reply-To: <20220309083753.1561921-1-liupeng256@huawei.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Mar 2022 03:07:48 -0500
Message-ID: <CAFd5g457_aWs2mbiD0Eq6Tz=8dpjJD9nHa+iK-RTe8H6kXwT=A@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] kunit: fix a UAF bug and do some optimization
To: Peng Liu <liupeng256@huawei.com>
Cc: glider@google.com, elver@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, wangkefeng.wang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XLRUu4GL;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Wed, Mar 9, 2022 at 3:19 AM 'Peng Liu' via KUnit Development
<kunit-dev@googlegroups.com> wrote:
>
> This series is to fix UAF when running kfence test case test_gfpzero,
> which is time costly. This UAF bug can be easily triggered by setting
> CONFIG_KFENCE_NUM_OBJECTS = 65535. Furthermore, some optimization for
> kunit tests has been done.

I was able to reproduce the error you described and can confirm that I
didn't see the UAF after applying your patches.

Tested-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g457_aWs2mbiD0Eq6Tz%3D8dpjJD9nHa%2BiK-RTe8H6kXwT%3DA%40mail.gmail.com.
