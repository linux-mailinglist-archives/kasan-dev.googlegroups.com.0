Return-Path: <kasan-dev+bncBDDL3KWR4EBRBNECROAQMGQEJXEYFDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id EFF803154A1
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 18:07:01 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id c15sf3021150pfn.9
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 09:07:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612890420; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gcta4jFp46wWXqLNMkLLDGB4BWChFfvDt0N2XJi263bBkUJ0dhmrDWQdBfv5BjAod1
         yh7rr1zcNNWZ7r3c0RHpbWmeWgPUsww6TTJNMDmEHqmiviaNbfTbHYdYpyE1gQakQe+C
         2ZC682IdAcYd4pIbse+38kF62vJq7AFVdS47/HlOppkd8pWNnJmjGhkIBlL/sg7NWTxw
         +AZHAoTH8LPFh5OhjEBDAQXRneqxUESs7OkcwaM50QIsqezy83AS7VPoUYzSY4YS0OLe
         ZWsDIDwSzboESNFswEE8gXMd/ecdF5hO59ddgIXUNEU8inUk7XwWgluBOAhHiTvFgWPh
         9l2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gdLnKZKFMRqTn+5a6c9mHwl+ej+0u1qiBVVC8QXhejA=;
        b=nJjm6p3bpp8BxNNsrJhYgaEqYj/4T0EP3fgfJeLuGsNzlUWm+qlSiFVQ0hW1Z8vwBg
         /0yiGP6vW/kuZyhn2zIkKRhxZHNSLcWBg/wnFIIsMzvR1bdYFN3rpzccdthV64sQ1Uok
         vpYDZDIxS4D4EAuympyAOY22/dhjBg38KDBL4jcXEMu1Quomx2Cw6JOabZKt/hs49N+U
         29V9ZvWi9kdk6k4QatQeGacEAZdow91vW2tWXeYivCBjVlnOfLWqUqRW2Vtm4FSfI6lj
         ZQqnZe0DmEpqv2bjAP4zmv/HqeTzlOfrLQIJP7efBmxeNreVAti/SVjnFjA6V1sz1t86
         sMqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gdLnKZKFMRqTn+5a6c9mHwl+ej+0u1qiBVVC8QXhejA=;
        b=SQlXjbHM1Ml4yjTo9sfrePnefxvh1UCK7XdZgZY+ekT37+QF+6Fixdkg8dNt+AI5lK
         HS3dn9mzbjfUo+0IpkvDAYyikJYUFHq6tY86JuAZ9uZqVqOeBBj+x7EuZ/0evfvZNynH
         VAM0MBpIi//3MokTGBEQMrDeqIQwbtnn/JmgQv95jVySJNxOjENIYj10DKhDyP9atgKV
         qAbSaOxGnRm+aPm90Bo3Emm7FOkDVQ1+izQ0g9KVtEMhOEzGpYPIW+rDSkXfNPeSoHmw
         veU7L+m/7YZ/VycXnA21R5dJlTN7dwXjl+eLlxM+I3MA90+tr0DygDz1oruJVoPxGvNZ
         GOeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gdLnKZKFMRqTn+5a6c9mHwl+ej+0u1qiBVVC8QXhejA=;
        b=GGwPun6RKu0V6ntRjbfMcB5g4RNPCw1ZmRYMMscX8P3DvLTdTjRigLa2x8qLHyw1RX
         XJ/dNEWNjWPix3JYZLUngkmcd6zplL5056016QlGp/HIPWtsDbvUnvKgfvrVObKGsQbD
         l+nx8FqSIxxjyDSlhlJcFOyXRT3we3SQeMq9NMNY7OaxlInPh535c49pn5mubrvrYshr
         DYXYHfiwjuMnL7IF9DdfXwe/1sJ2JeSSo6aKZHLR9mOcIH9oMSOHGtlAI8BmAOxaNjWU
         saTSzXKQSzI/U4Xzs9fI9mCY5asdK997VxkqDJ4MdyrVuE3FF/KhLhYBkaDnrP0SRSlp
         48Ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MRAVIhYvtGDpaOhxFCeoBKuAp6OnsXZfEBMFNRHLQaulgMSnZ
	zCqHFNqYaqPZJAGaoasyzhE=
X-Google-Smtp-Source: ABdhPJwaW5fBM1piOi//IljndlgcdWrp3/RqZ5p30WObJHk3LS+JbZ3X1Qzuf6Lhlo7AnZXmxZqu8g==
X-Received: by 2002:a63:dc06:: with SMTP id s6mr22803259pgg.358.1612890420743;
        Tue, 09 Feb 2021 09:07:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31c7:: with SMTP id v7ls4310535ple.2.gmail; Tue, 09
 Feb 2021 09:07:00 -0800 (PST)
X-Received: by 2002:a17:90a:fd01:: with SMTP id cv1mr4869524pjb.77.1612890420072;
        Tue, 09 Feb 2021 09:07:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612890420; cv=none;
        d=google.com; s=arc-20160816;
        b=QIW3pLi3Xafa3lIfGvLxFguOGm6ueywDUXHi62YilOj06io4iKl/9gKTVPAVhfg8PQ
         iNRXNHIMBhl5fKSdlGgtBZHTuKCKttDw0CtkM1G2fS7CKrV2gV4n3ihsx1ij7fRDckGV
         PqWqFCvEHra6UWUR1ZM3EARqJ97Ue0jaRsbMS1RK8SlsbaVfOEk2UpNYsqJ6Q6VEcIWt
         3DsAqyQ16dsTvE1HhvSnHhhy/m/s1AE7+TY6tPlEfzahtfsivjc3YW112zA3VyWjhtlV
         gIt8vHyRi/YGXoV7ey19/qsdWm82veisVDzAB1bGDqHdF7vgVakhbR0ZqHKlUCTAS+M/
         QnxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=LzjB8ka6EojWgpqNO3KKEiUmFzzHgbTbu9WeHACwuV4=;
        b=nnU/9PAdCtYxuRvEstGoN1shdsqyD3oD6P/OQfmroSFi0yMSic2ZtaxmWEyi5e2c9t
         7htBniuCJxkRdTwohLvJ7UHx+j6rSOuPoulC0qMiFDDKOtvMhg7U2ZllYhJmOnybaPJ5
         YhsSlqn05hk+nTvT+sxCEqfpu2UWHebPPHYQAr5spRCD6r7nLVatAEILI86GlKf2Q4b+
         lsi210GDMODHMTlqvPqolBvHKu351sl7bEXIAY+tlaO2I3o4zQ408cGgZyJJv8oqKASD
         3cVAfQtaIBHNQ5Aocowc6X5v4YyFZPlwbd/U5H8SP36rILxe97vX66Ws++mfUacXV6w2
         iERQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l8si490675plg.2.2021.02.09.09.07.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Feb 2021 09:07:00 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5556D64E31;
	Tue,  9 Feb 2021 17:06:57 +0000 (UTC)
Date: Tue, 9 Feb 2021 17:06:54 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v12 7/7] kasan: don't run tests in async mode
Message-ID: <20210209170654.GH1435@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-8-vincenzo.frascino@arm.com>
 <20210209120241.GF1435@arm.com>
 <0e373526-0fa8-c5c0-fb41-5c17aa47f07c@arm.com>
 <CAAeHK+yj9PR2Tw_xrpKKh=8GyNwgOaEu1pK8L6XL4zz0NtVs3A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+yj9PR2Tw_xrpKKh=8GyNwgOaEu1pK8L6XL4zz0NtVs3A@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Feb 09, 2021 at 04:02:25PM +0100, Andrey Konovalov wrote:
> On Tue, Feb 9, 2021 at 1:16 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
> > On 2/9/21 12:02 PM, Catalin Marinas wrote:
> > > On Mon, Feb 08, 2021 at 04:56:17PM +0000, Vincenzo Frascino wrote:
> > >> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > >> index 7285dcf9fcc1..f82d9630cae1 100644
> > >> --- a/lib/test_kasan.c
> > >> +++ b/lib/test_kasan.c
> > >> @@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
> > >>              kunit_err(test, "can't run KASAN tests with KASAN disabled");
> > >>              return -1;
> > >>      }
> > >> +    if (kasan_flag_async) {
> > >> +            kunit_err(test, "can't run KASAN tests in async mode");
> > >> +            return -1;
> > >> +    }
> > >>
> > >>      multishot = kasan_save_enable_multi_shot();
> > >>      hw_set_tagging_report_once(false);
> > >
> > > I think we can still run the kasan tests in async mode if we check the
> > > TFSR_EL1 at the end of each test by calling mte_check_tfsr_exit().
> > >
> >
> > IIUC this was the plan for the future. But I let Andrey comment for more details.
> 
> If it's possible to implement, then it would be good to have. Doesn't
> have to be a part of this series though.

I think it can be part of this series but after the 5.12 merging window
(we are a few days away from final 5.11 and I don't think we should
rush the MTE kernel async support in).

It would be nice to have the kasan tests running with async by the time
we merge the patches (at a quick look, I think it's possible but, of
course, we may hit some blockers when implementing it).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209170654.GH1435%40arm.com.
