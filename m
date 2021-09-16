Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSWORWFAMGQEZY2KE3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FBFF40DE7D
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 17:48:28 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id b84-20020a253457000000b0059e6b730d45sf24256586yba.6
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 08:48:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631807307; cv=pass;
        d=google.com; s=arc-20160816;
        b=YTDOuGzCoKEwpKDzesNGjA5Nw2bC+YouM5wcr7huw3VoBNPjB58ZetUqNBa4ernX5z
         3PzNIAQMaCkqMEuq62CjCpRUE2qHDNiAhTe2djSGlWrmyJxF790WCkEIiyCpshba1tKu
         BeG9SQcPfID9LZDLfpLFteVmD1OrgYuyOxeJi8ZC7jMkmGVXF//SPTzr/GrgiMuK7Jmm
         YqiEE8f6L3dFpqOxHHQX35fFnuueTSa7EY9PifEYn1PSxNpBvviuZxoUcxXOmkBdHo0I
         WfO5NDF7RtxP5A3mfZ/ROpa859l/z7qapXnaFeRQ6ykK0ABXksbStZAWQ/1Tjy/Be2L3
         M6dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lzOTS5TINSoefcOu56iyHX3c1mLSu+cd5fwGharnEQw=;
        b=j78WlmwpJV3Rq9ia3nV+tuIyNgoZTixC+VWpsm21hnQMi/j77FaX4IVfBOKwm3nhx5
         rYGRfvbyPde4yRxeDgLq08bLYarozK+1PNKsbIXnw5qsU/MF1+wmj+tXQNE/iHoSNJs1
         05yz24pSYWNtie4CKMUkm6l8jKHPZOW0M7t4IhPbhnGNDtbmTwGdF3YLT/aF7Fmq8FEF
         H6YSjkFUrgho1VL4ChoTaFBioiRb7VTeF1+BCGfAJp3ONTRpWwO03us0lVMHPkFZptR/
         lR5O6Dwl4LpDkcxmrQ4rVga9y+UYlZQivNl4PuHHdMx4inCfrSllyaxgJgL6v5WIzpJ5
         oG8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="r9/FKsGR";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lzOTS5TINSoefcOu56iyHX3c1mLSu+cd5fwGharnEQw=;
        b=czNQ9xse0rCH0XVkshuAPwbd9YHoHHp2ImW55fnDbCaDdX/OjicB6MSjwe/7BkO9kd
         Bw8bXr4MZLhSZXVV+yv75YZ/gTb4oyg7rXOAWhW/N0ACl5ACmGwcQS1H4MQ0gsS9Im9J
         oODhtenXODKxo8G4NzlYQ3iiSUFThVdkKPnB53/UkDVao66icKvKjvXV9z1ibzXEjE/B
         GCnSXuADCKu6R4NE1RO+bY6whZTSodHXnK9koGr4HiKCOs6W7bGHHY/nnP23/0hK968o
         vxU8KD/OmVbCVWJwKdh3LI3JraCM4SZXwY+4JHOqaF7tCBUIxiGfQDVGkzSZACUFDogi
         fHtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lzOTS5TINSoefcOu56iyHX3c1mLSu+cd5fwGharnEQw=;
        b=xhbBxwJLdTS9apCwjoPQtKsTwI4pYm9JyFK/r7vZaM7fqry6Pz5L3n31Bq7o9JvqeJ
         DViF08pCkS9WIYR5kyi7Mh3QUFk6kKUGXodQX90solJMFXWf8eVTsGvQzicqcecEUlfK
         Q2FDLbRXzUkkFalDAxSF/V82mZKhjhFYEFk4njA0hPa8z9iOaLjTDNvC0kiu3XD6TPwU
         1o7mXpJF7MOWOXtttfrNhWO2kWOqNQpgYkge5zI2e+tDzgWBeldmlfk1xrP5VqEizTE2
         CcRgJCqrgzX97DRQ0hRSrXgFc4tLDLu9PKH4JGagjGWzG5ijWqV68591eO+ndFJ7mvaZ
         0drQ==
X-Gm-Message-State: AOAM533sQi8TiNGWB6DrQsvhLGwYmI+JfJjjEdrfGRsgrUZHXIJoigek
	SWYo5k6mY8lEvNDTFSnYsgc=
X-Google-Smtp-Source: ABdhPJyh4TJlLmxGALvhwQlKWOmZBT1TvrFiu0d104DGl4s7nwokiI9t47W0jGsKLPTioAhvspEwsg==
X-Received: by 2002:a5b:bc3:: with SMTP id c3mr7832047ybr.132.1631807307013;
        Thu, 16 Sep 2021 08:48:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d055:: with SMTP id h82ls935102ybg.6.gmail; Thu, 16 Sep
 2021 08:48:26 -0700 (PDT)
X-Received: by 2002:a25:ab90:: with SMTP id v16mr8024353ybi.146.1631807306533;
        Thu, 16 Sep 2021 08:48:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631807306; cv=none;
        d=google.com; s=arc-20160816;
        b=ADOHRKZQCD7qQFY+kbD7lBcKj9QHQXhTYyJvb7NKgANGZE64Uuv7hnt8umL+fAHXP1
         VS/b8n0x354HsqQToNek0w/cxlAgx1iUszWZT7NVLftPRtD2CYEOQtEkNZhppZCTsnz6
         LX74nNR9gvAOL2GXmPTEEjVStzlgQP1yjCLO2srod+hliZ/5Ka3mqvjPF6I51UFdO2Cl
         OWjHs/U7tMtpePCuF7CnJ3W0cawLiInNsg+0vjPlP4tgtD4MBg6JIbO+DlMhm5JCd6Cs
         /746NjB6UXRKTuhiqpTA3T31prpJMZqSUA+OkGlhomywoXQKypJlRSB8YI6NGRvuLXt3
         Rkzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rD3TrezbVLYHxHI60H3QOHHxKkUHFG/XFIP2soX5eXI=;
        b=TkXR49Q+iceWOVu7mEee3xLUFPKvcPOG1ieu8C7rkoaeEUvkltYF0BmuFU4s3Y/zQn
         1ohNBRbnShXaUx99wsTK5wstKrugf+RHEmh0K3caiM1QIMO+O17vnVEupySGCC8IVIhT
         YECwWLtalsB29b7dqoviqtc4B1WA6qbXMy/A1E7UACCFTghw1fvkR1pgQXMw01f+7gVP
         BjNE++FPKPXU4LDO/KzjyELC/rDjToGn2swHhIOIj441QIUr9NwKDo1pwhNTVSOmVOXd
         2LLgD7BLA4peeOmrTN5mlz4w7tAbTKG/q03k2CmpH0ZHQXKWRiijJybGkE+z8a20Bry2
         Zo+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="r9/FKsGR";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2f.google.com (mail-oo1-xc2f.google.com. [2607:f8b0:4864:20::c2f])
        by gmr-mx.google.com with ESMTPS id u17si483353ybc.5.2021.09.16.08.48.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Sep 2021 08:48:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) client-ip=2607:f8b0:4864:20::c2f;
Received: by mail-oo1-xc2f.google.com with SMTP id b5-20020a4ac285000000b0029038344c3dso2208041ooq.8
        for <kasan-dev@googlegroups.com>; Thu, 16 Sep 2021 08:48:26 -0700 (PDT)
X-Received: by 2002:a4a:4344:: with SMTP id l4mr4919522ooj.38.1631807305859;
 Thu, 16 Sep 2021 08:48:25 -0700 (PDT)
MIME-Version: 1.0
References: <20210421105132.3965998-1-elver@google.com> <20210421105132.3965998-3-elver@google.com>
 <6c0d5f40-5067-3a59-65fa-6977b6f70219@huawei.com> <abd74d5a-1236-4f0e-c123-a41e56e22391@huawei.com>
 <858909f98f33478891056a840ad68b9f@AcuMS.aculab.com>
In-Reply-To: <858909f98f33478891056a840ad68b9f@AcuMS.aculab.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Sep 2021 17:48:14 +0200
Message-ID: <CANpmjNPXNM-di-XwW52Hh5kEv9BPSh_Aw75yFQpu81e1kUfGtA@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
To: David Laight <David.Laight@aculab.com>
Cc: Kefeng Wang <wangkefeng.wang@huawei.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, "glider@google.com" <glider@google.com>, 
	"dvyukov@google.com" <dvyukov@google.com>, "jannh@google.com" <jannh@google.com>, 
	"mark.rutland@arm.com" <mark.rutland@arm.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "hdanton@sina.com" <hdanton@sina.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="r9/FKsGR";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, 16 Sept 2021 at 17:45, David Laight <David.Laight@aculab.com> wrote:
>
> From: Kefeng Wang
> > Sent: 16 September 2021 02:21
> >
> > We found kfence_test will fails  on ARM64 with this patch with/without
> > CONFIG_DETECT_HUNG_TASK,
> >
> > Any thought ?
> >
> ...
> > >>       /* Enable static key, and await allocation to happen. */
> > >>       static_branch_enable(&kfence_allocation_key);
> > >>   -    wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
> > >> +    if (sysctl_hung_task_timeout_secs) {
> > >> +        /*
> > >> +         * During low activity with no allocations we might wait a
> > >> +         * while; let's avoid the hung task warning.
> > >> +         */
> > >> +        wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate),
> > >> +                   sysctl_hung_task_timeout_secs * HZ / 2);
> > >> +    } else {
> > >> +        wait_event(allocation_wait, atomic_read(&kfence_allocation_gate));
> > >> +    }
> > >>         /* Disable static key and reset timer. */
> > >>       static_branch_disable(&kfence_allocation_key);
>
> It has replaced a wait_event_timeout() with a wait_event().
>
> That probably isn't intended.
> Although I'd expect their to be some test for the wait being
> signalled or timing out.

It is intended -- there's a wake_up() for this. See the whole patch
series for explanation.

The whole reason we had the timeout was to avoid the hung task
warnings, but we can do better if there is no hung task warning
enabled.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPXNM-di-XwW52Hh5kEv9BPSh_Aw75yFQpu81e1kUfGtA%40mail.gmail.com.
