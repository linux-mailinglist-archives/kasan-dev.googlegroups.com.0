Return-Path: <kasan-dev+bncBC7OBJGL2MHBB37VVXBQMGQERYL7O6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id BB647AFAD79
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 09:44:50 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2d9ea524aa6sf2928780fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 00:44:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751874288; cv=pass;
        d=google.com; s=arc-20240605;
        b=NRj34kTzEKtnbyZ+ES/BlWG8hvgSFOgbgekevng7bQ53e65/iNCZUUbSkWSAyF2B//
         th6LJHfT/5+ceIzx1t6vZuRwVjp93q6ghhosxfPtTwjqgdX3t+HTkAUqv+2oJOyqIVcN
         QD4smD0+fh52kAeU+TGsQ7lQoaQM4W3meyR+ylwdsy9kbi7Dyr+suXr3Eeh5L8e/mL4B
         1rDomTwvDMWVHhAPGVir8HE/DdSwADJIlo6/bJRezNEslry4q1KNNwu0dmJCT4WraeWK
         npoIVIQC3txUiujrzdJO4lzbJ/ho23/ztV3Ply/Wv+9Aeudup+e4jPUxg/ibzQmthPi9
         OWgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KOntY69huHY/RZjACY4qqGBt+FfeJEF+ab5RV9Fz9TQ=;
        fh=Wqd6wF5q9jUdcTi96mzADp9p3oZkxfByuk+j3vmjwfg=;
        b=NZ4R01NIZXc25Q1cpu2dcJwyFrXvDJxFN4Y8iVfwgT4X7dymFggIGif+BQGFexPbr5
         yX/X0YZhpJ5rvNj2C2b5t1CLz6109L6NyrsrlzYV4iNvU5IhIuo40XLi0DS0/526Q4jI
         ApdByjfq2Rb9f2EFCKmYTQnHE//Mob4NIWGns8WBQgZxyTy3uXCkC/GNqMSV10C9pDfq
         oqEvRRcBPuWSEL+TqHGuVhci1Y5Dp1Vl/V0REDk+lSVhlPwXBhLDwLiqBwFqruDNlzg7
         bcSjpvbAurqAg9UXlmu8UMVd/bMTRDKmzWz55OV51tYHQbcD1kc3mTv8DULZxWm8TV2B
         6IBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="UL/AV/SX";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751874288; x=1752479088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KOntY69huHY/RZjACY4qqGBt+FfeJEF+ab5RV9Fz9TQ=;
        b=ADArbEvnbIWQMccHeWRCzr8pxuHU2V2k0H0KmsYtkwIfaIfDxqMWaCGzCBjqze4zCp
         Pr8w0TU+/j1usIqerx3oijjYdrdI+OugUMrmwfweT6BJQZpUdDumkGPSxyjes7nTgZcK
         G8lQUKTllstuSgn7IQZQ8HINfHHJHm4KS+vzVKWqPY+hfjInWWdGdceBV/a+mwREXOtT
         St3u8I117cMYfnFpNKhDFAX/vx6UJp0LxnBFxm8DS+6miIpQWHVqEFQm0jThXNOcZbAw
         NNfmXRoriMIL2CJyqvVC2Jn7BaPFIUI7VObZCS3Bk0kGnvbEcP6Q8qDBJnPCXk8IxFkL
         VAAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751874288; x=1752479088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KOntY69huHY/RZjACY4qqGBt+FfeJEF+ab5RV9Fz9TQ=;
        b=Csq7qFJVUYZW51dhgcwDR9OuM9hUzHZpoBbR5uSGzLuk5oDTvsNOzUkVHXhXeC0AaT
         dod+imw0j0u9VeZauz3Y4nG2o0v4CoZIK/FqsHJXqJ+qE4LuS5+kFrT6G5j2kgzGc4B3
         yr0OgZ2TazBDlRpi9AEoGKwJnDAWMziKe27FSwLLeahUMHfhJC7jHAT6l6yXvCzEEBEA
         2PhgVpl1YqEYHYP81B1/FBc1l5e+QEMO0Rvvnr2nMRg8MUL5yT34Es7tky92kW0bJO8V
         km8z/Roiy4WSaocVr5rlP/DxhHFlxpE7PkhO2Br+jXPpKqgEiJ07PKMXtfTAd7+cKb/l
         tCPQ==
X-Forwarded-Encrypted: i=2; AJvYcCVKYWnaXFDezMmqy+mJ9YicvS91uQMXoyS7pBsrEnDIXHXVDFP4kw4CGc5tCWnTeEBUbn8svg==@lfdr.de
X-Gm-Message-State: AOJu0YyOG8905FoLbcrHeoDbPC1eksJCdHFOPxZQqfCrpzaEK5ZzRzc2
	H+h4A1b3eMmGlP1B8t7mfnfAvsMGah8GyTXlMTaOhwEU1K9nz2Z1XDFT
X-Google-Smtp-Source: AGHT+IFYTwoaCHfU1PbZYcy52Q9Us51vJ55SrTizH/E+zopa3LTBvMWYkN9BUnZUVH43CedTcUS44A==
X-Received: by 2002:a05:6870:c1ce:b0:2e9:9118:9ed1 with SMTP id 586e51a60fabf-2f7969c026bmr7671478fac.3.1751874288003;
        Mon, 07 Jul 2025 00:44:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdXXP/Lc9/siP4uqAzlAqSaDagaDGalQ+H8tNXPQNz1DQ==
Received: by 2002:a05:6871:a182:b0:2ef:586a:a700 with SMTP id
 586e51a60fabf-2f79b153fe3ls778642fac.0.-pod-prod-08-us; Mon, 07 Jul 2025
 00:44:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMxAFSO+tzE/xifYPqe/W0OhWs0kaxrCFD5hpUMzQNLQwmw+gUo3nZIFYG2Xe+ZytHZuAQOUwnf4Y=@googlegroups.com
X-Received: by 2002:a05:6808:1529:b0:404:a28c:ca4b with SMTP id 5614622812f47-40d073ccef9mr7414470b6e.20.1751874287068;
        Mon, 07 Jul 2025 00:44:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751874287; cv=none;
        d=google.com; s=arc-20240605;
        b=i4V88RrNn0q3ffhNkb93bJnBMzR+fpRpTrYr42nEy5c0Onomg5nSb9BjNorFR2SSUJ
         35j0Ba3+1LxtoeXXk19ave+0blUcZtG0X4NX4FNeX7oVW4PenXLs6IqWO27cmqwV+Vec
         SPdwZaOSeyJqHf6V9gSZBWqFLpr4tYGA9S2WlmLm99RaWvUAvROHMCm5eCUKPiyd5WV2
         pQBfMI8m/YKzzdkRzfyd7dBby2keHHXsyNF5ACOw8psGsnHy7vMzOMqSoZodgT/AZh8M
         DoQRacIa1fEB+e5OEGHKygx1qSBVFtaxUGHiy1KSRrtpZCYuUK3UCp/65CrhqpNLnnRX
         x9Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RfbbtwUrlcYhOTf/0LYdK2gX0smrrnEPCZ4bjlr3z90=;
        fh=IvIbKM3UHeoSiSelVeIxfRRkzdN6mibtv+M0O9O/224=;
        b=aTuzq+Z9Gx4n1Rqbw4EBlGCzkNoDZ1009RI142G7gnoTJrbWCW9OWwBi6uOHfZWVM8
         EDXbX15GaPio2r1hkjCsz90cEbka74/witm+CLOJrDrcrjkbxrhnKgy5Ex7u6DFK0o0o
         D8IUueOJAfgBBUKBHMmJ68UPBzLhvIys6vCaWm3RGxu0wxfBL5RI6eKeowY540CHhItq
         JnJh3UT5f+Wwt2mNiwi19JmgT7wG7xcXI81ZicHbWCu6XBNXU3S3ynqG9QXGR2pEhF9q
         wtf5IKsuvvjDNoNepnUA1wz1cWJy06q0iBSTO+MgdSqVWaIaVgP8bm8rkmsL60CgupQ/
         4iTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="UL/AV/SX";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-40d02abc50dsi314237b6e.5.2025.07.07.00.44.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 00:44:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-313cde344d4so2662669a91.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 00:44:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWm+If6aRXTUmaIhCFbHL14XfrZoKB/dxm7w0aiGaSU8bRRmd17H/0engSYUmmErL+aiSmNHQDpUzk=@googlegroups.com
X-Gm-Gg: ASbGnct6XhLDNtZHPKJRmAH5s1U1jOhI3Zfw357XqCdHuatwEVHA7hmzdd/qv3Mm3st
	YjG9Wit6U1M3HhdUyrrbfBQl1Yq6TLaWowygU8dUiEGEllUkaB8DungeEfEIn28C+L3LoNlojGB
	x1bqgnl2Fw94IjMECqErdte8KbSMNtN6pmFcYTSIJ1xrDKCMoPeLGKqT40jC1QBeTwMPky/Ftrh
	g==
X-Received: by 2002:a17:90b:1a8d:b0:312:1b53:5e9f with SMTP id
 98e67ed59e1d1-31aaddb6cb4mr16827244a91.24.1751874285808; Mon, 07 Jul 2025
 00:44:45 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
In-Reply-To: <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Jul 2025 09:44:09 +0200
X-Gm-Features: Ac12FXzv2-oPeEX56Hh2E61FEUd4lH0DkpiQCIi8_un7sJzh52udAzGZo6YFXNo
Message-ID: <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Chao Yu <chao.yu@oppo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="UL/AV/SX";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as
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

On Mon, 7 Jul 2025 at 07:06, Alejandro Colomar <alx@kernel.org> wrote:
>
> While doing this, I detected some anomalies in the existing code:
>
> mm/kfence/kfence_test.c:
>
>         -  The last call to scnprintf() did increment 'cur', but it's
>            unused after that, so it was dead code.  I've removed the dead
>            code in this patch.

That was done to be consistent with the other code for readability,
and to be clear where the next bytes should be appended (if someone
decides to append more). There is no runtime dead code, the compiler
optimizes away the assignment. But I'm indifferent, so removing the
assignment is fine if you prefer that.

Did you run the tests? Do they pass?


>         -  'end' is calculated as
>
>                 end = &expect[0][sizeof(expect[0] - 1)];
>
>            However, the '-1' doesn't seem to be necessary.  When passing
>            $2 to scnprintf(), the size was specified as 'end - cur'.
>            And scnprintf() --just like snprintf(3)--, won't write more
>            than $2 bytes (including the null byte).  That means that
>            scnprintf() wouldn't write more than
>
>                 &expect[0][sizeof(expect[0]) - 1] - expect[0]
>
>            which simplifies to
>
>                 sizeof(expect[0]) - 1
>
>            bytes.  But we have sizeof(expect[0]) bytes available, so
>            we're wasting one byte entirely.  This is a benign off-by-one
>            bug.  The two occurrences of this bug will be fixed in a
>            following patch in this series.
>
> mm/kmsan/kmsan_test.c:
>
>         The same benign off-by-one bug calculating the remaining size.


Same - does the test pass?

> mm/mempolicy.c:
>
>         This file uses the 'p += snprintf()' anti-pattern.  That will
>         overflow the pointer on truncation, which has undefined
>         behavior.  Using seprintf(), this bug is fixed.
>
>         As in the previous file, here there was also dead code in the
>         last scnprintf() call, by incrementing a pointer that is not
>         used after the call.  I've removed the dead code.
>
> mm/page_owner.c:
>
>         Within print_page_owner(), there are some calls to scnprintf(),
>         which do report truncation.  And then there are other calls to
>         snprintf(), where we handle errors (there are two 'goto err').
>
>         I've kept the existing error handling, as I trust it's there for
>         a good reason (i.e., we may want to avoid calling
>         print_page_owner_memcg() if we truncated before).  Please review
>         if this amount of error handling is the right one, or if we want
>         to add or remove some.  For seprintf(), a single test for null
>         after the last call is enough to detect truncation.
>
> mm/slub.c:
>
>         Again, the 'p += snprintf()' anti-pattern.  This is UB, and by
>         using seprintf() we've fixed the bug.
>
> Fixes: f99e12b21b84 (2021-07-30; "kfence: add function to mask address bits")
> [alx: that commit introduced dead code]
> Fixes: af649773fb25 (2024-07-17; "mm/numa_balancing: teach mpol_to_str about the balancing mode")
> [alx: that commit added p+=snprintf() calls, which are UB]
> Fixes: 2291990ab36b (2008-04-28; "mempolicy: clean-up mpol-to-str() mempolicy formatting")
> [alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
> Fixes: 948927ee9e4f (2013-11-13; "mm, mempolicy: make mpol_to_str robust and always succeed")
> [alx: that commit changes old code into p+=snprintf(), which is still UB]
> [alx: that commit also produced dead code by leaving the last 'p+=...']
> Fixes: d65360f22406 (2022-09-26; "mm/slub: clean up create_unique_id()")
> [alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
> Cc: Kees Cook <kees@kernel.org>
> Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
> Cc: Sven Schnelle <svens@linux.ibm.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Heiko Carstens <hca@linux.ibm.com>
> Cc: Tvrtko Ursulin <tvrtko.ursulin@igalia.com>
> Cc: "Huang, Ying" <ying.huang@intel.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Lee Schermerhorn <lee.schermerhorn@hp.com>
> Cc: Linus Torvalds <torvalds@linux-foundation.org>
> Cc: David Rientjes <rientjes@google.com>
> Cc: Christophe JAILLET <christophe.jaillet@wanadoo.fr>
> Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Cc: Chao Yu <chao.yu@oppo.com>
> Cc: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Alejandro Colomar <alx@kernel.org>
> ---
>  mm/kfence/kfence_test.c | 24 ++++++++++++------------
>  mm/kmsan/kmsan_test.c   |  4 ++--
>  mm/mempolicy.c          | 18 +++++++++---------
>  mm/page_owner.c         | 32 +++++++++++++++++---------------
>  mm/slub.c               |  5 +++--
>  5 files changed, 43 insertions(+), 40 deletions(-)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 00034e37bc9f..ff734c514c03 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -113,26 +113,26 @@ static bool report_matches(const struct expect_report *r)
>         end = &expect[0][sizeof(expect[0]) - 1];
>         switch (r->type) {
>         case KFENCE_ERROR_OOB:
> -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds %s",
> +               cur = seprintf(cur, end, "BUG: KFENCE: out-of-bounds %s",
>                                  get_access_type(r));
>                 break;
>         case KFENCE_ERROR_UAF:
> -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free %s",
> +               cur = seprintf(cur, end, "BUG: KFENCE: use-after-free %s",
>                                  get_access_type(r));
>                 break;
>         case KFENCE_ERROR_CORRUPTION:
> -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: memory corruption");
> +               cur = seprintf(cur, end, "BUG: KFENCE: memory corruption");
>                 break;
>         case KFENCE_ERROR_INVALID:
> -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid %s",
> +               cur = seprintf(cur, end, "BUG: KFENCE: invalid %s",
>                                  get_access_type(r));
>                 break;
>         case KFENCE_ERROR_INVALID_FREE:
> -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid free");
> +               cur = seprintf(cur, end, "BUG: KFENCE: invalid free");
>                 break;
>         }
>
> -       scnprintf(cur, end - cur, " in %pS", r->fn);
> +       seprintf(cur, end, " in %pS", r->fn);
>         /* The exact offset won't match, remove it; also strip module name. */
>         cur = strchr(expect[0], '+');
>         if (cur)
> @@ -144,26 +144,26 @@ static bool report_matches(const struct expect_report *r)
>
>         switch (r->type) {
>         case KFENCE_ERROR_OOB:
> -               cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
> +               cur = seprintf(cur, end, "Out-of-bounds %s at", get_access_type(r));
>                 addr = arch_kfence_test_address(addr);
>                 break;
>         case KFENCE_ERROR_UAF:
> -               cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
> +               cur = seprintf(cur, end, "Use-after-free %s at", get_access_type(r));
>                 addr = arch_kfence_test_address(addr);
>                 break;
>         case KFENCE_ERROR_CORRUPTION:
> -               cur += scnprintf(cur, end - cur, "Corrupted memory at");
> +               cur = seprintf(cur, end, "Corrupted memory at");
>                 break;
>         case KFENCE_ERROR_INVALID:
> -               cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
> +               cur = seprintf(cur, end, "Invalid %s at", get_access_type(r));
>                 addr = arch_kfence_test_address(addr);
>                 break;
>         case KFENCE_ERROR_INVALID_FREE:
> -               cur += scnprintf(cur, end - cur, "Invalid free of");
> +               cur = seprintf(cur, end, "Invalid free of");
>                 break;
>         }
>
> -       cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);
> +       seprintf(cur, end, " 0x%p", (void *)addr);
>
>         spin_lock_irqsave(&observed.lock, flags);
>         if (!report_available())
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 9733a22c46c1..a062a46b2d24 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -107,9 +107,9 @@ static bool report_matches(const struct expect_report *r)
>         cur = expected_header;
>         end = &expected_header[sizeof(expected_header) - 1];
>
> -       cur += scnprintf(cur, end - cur, "BUG: KMSAN: %s", r->error_type);
> +       cur = seprintf(cur, end, "BUG: KMSAN: %s", r->error_type);
>
> -       scnprintf(cur, end - cur, " in %s", r->symbol);
> +       seprintf(cur, end, " in %s", r->symbol);
>         /* The exact offset won't match, remove it; also strip module name. */
>         cur = strchr(expected_header, '+');
>         if (cur)
> diff --git a/mm/mempolicy.c b/mm/mempolicy.c
> index b28a1e6ae096..c696e4a6f4c2 100644
> --- a/mm/mempolicy.c
> +++ b/mm/mempolicy.c
> @@ -3359,6 +3359,7 @@ int mpol_parse_str(char *str, struct mempolicy **mpol)
>  void mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol)
>  {
>         char *p = buffer;
> +       char *e = buffer + maxlen;
>         nodemask_t nodes = NODE_MASK_NONE;
>         unsigned short mode = MPOL_DEFAULT;
>         unsigned short flags = 0;
> @@ -3384,33 +3385,32 @@ void mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol)
>                 break;
>         default:
>                 WARN_ON_ONCE(1);
> -               snprintf(p, maxlen, "unknown");
> +               seprintf(p, e, "unknown");
>                 return;
>         }
>
> -       p += snprintf(p, maxlen, "%s", policy_modes[mode]);
> +       p = seprintf(p, e, "%s", policy_modes[mode]);
>
>         if (flags & MPOL_MODE_FLAGS) {
> -               p += snprintf(p, buffer + maxlen - p, "=");
> +               p = seprintf(p, e, "=");
>
>                 /*
>                  * Static and relative are mutually exclusive.
>                  */
>                 if (flags & MPOL_F_STATIC_NODES)
> -                       p += snprintf(p, buffer + maxlen - p, "static");
> +                       p = seprintf(p, e, "static");
>                 else if (flags & MPOL_F_RELATIVE_NODES)
> -                       p += snprintf(p, buffer + maxlen - p, "relative");
> +                       p = seprintf(p, e, "relative");
>
>                 if (flags & MPOL_F_NUMA_BALANCING) {
>                         if (!is_power_of_2(flags & MPOL_MODE_FLAGS))
> -                               p += snprintf(p, buffer + maxlen - p, "|");
> -                       p += snprintf(p, buffer + maxlen - p, "balancing");
> +                               p = seprintf(p, e, "|");
> +                       p = seprintf(p, e, "balancing");
>                 }
>         }
>
>         if (!nodes_empty(nodes))
> -               p += scnprintf(p, buffer + maxlen - p, ":%*pbl",
> -                              nodemask_pr_args(&nodes));
> +               seprintf(p, e, ":%*pbl", nodemask_pr_args(&nodes));
>  }
>
>  #ifdef CONFIG_SYSFS
> diff --git a/mm/page_owner.c b/mm/page_owner.c
> index cc4a6916eec6..5811738e3320 100644
> --- a/mm/page_owner.c
> +++ b/mm/page_owner.c
> @@ -496,7 +496,7 @@ void pagetypeinfo_showmixedcount_print(struct seq_file *m,
>  /*
>   * Looking for memcg information and print it out
>   */
> -static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
> +static inline char *print_page_owner_memcg(char *p, const char end[0],
>                                          struct page *page)
>  {
>  #ifdef CONFIG_MEMCG
> @@ -511,8 +511,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
>                 goto out_unlock;
>
>         if (memcg_data & MEMCG_DATA_OBJEXTS)
> -               ret += scnprintf(kbuf + ret, count - ret,
> -                               "Slab cache page\n");
> +               p = seprintf(p, end, "Slab cache page\n");
>
>         memcg = page_memcg_check(page);
>         if (!memcg)
> @@ -520,7 +519,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
>
>         online = (memcg->css.flags & CSS_ONLINE);
>         cgroup_name(memcg->css.cgroup, name, sizeof(name));
> -       ret += scnprintf(kbuf + ret, count - ret,
> +       p = seprintf(p, end,
>                         "Charged %sto %smemcg %s\n",
>                         PageMemcgKmem(page) ? "(via objcg) " : "",
>                         online ? "" : "offline ",
> @@ -529,7 +528,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
>         rcu_read_unlock();
>  #endif /* CONFIG_MEMCG */
>
> -       return ret;
> +       return p;
>  }
>
>  static ssize_t
> @@ -538,14 +537,16 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
>                 depot_stack_handle_t handle)
>  {
>         int ret, pageblock_mt, page_mt;
> -       char *kbuf;
> +       char *kbuf, *p, *e;
>
>         count = min_t(size_t, count, PAGE_SIZE);
>         kbuf = kmalloc(count, GFP_KERNEL);
>         if (!kbuf)
>                 return -ENOMEM;
>
> -       ret = scnprintf(kbuf, count,
> +       p = kbuf;
> +       e = kbuf + count;
> +       p = seprintf(p, e,
>                         "Page allocated via order %u, mask %#x(%pGg), pid %d, tgid %d (%s), ts %llu ns\n",
>                         page_owner->order, page_owner->gfp_mask,
>                         &page_owner->gfp_mask, page_owner->pid,
> @@ -555,7 +556,7 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
>         /* Print information relevant to grouping pages by mobility */
>         pageblock_mt = get_pageblock_migratetype(page);
>         page_mt  = gfp_migratetype(page_owner->gfp_mask);
> -       ret += scnprintf(kbuf + ret, count - ret,
> +       p = seprintf(p, e,
>                         "PFN 0x%lx type %s Block %lu type %s Flags %pGp\n",
>                         pfn,
>                         migratetype_names[page_mt],
> @@ -563,22 +564,23 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
>                         migratetype_names[pageblock_mt],
>                         &page->flags);
>
> -       ret += stack_depot_snprint(handle, kbuf + ret, count - ret, 0);
> -       if (ret >= count)
> -               goto err;
> +       p = stack_depot_seprint(handle, p, e, 0);
> +       if (p == NULL)
> +               goto err;  // XXX: Should we remove this error handling?
>
>         if (page_owner->last_migrate_reason != -1) {
> -               ret += scnprintf(kbuf + ret, count - ret,
> +               p = seprintf(p, e,
>                         "Page has been migrated, last migrate reason: %s\n",
>                         migrate_reason_names[page_owner->last_migrate_reason]);
>         }
>
> -       ret = print_page_owner_memcg(kbuf, count, ret, page);
> +       p = print_page_owner_memcg(p, e, page);
>
> -       ret += snprintf(kbuf + ret, count - ret, "\n");
> -       if (ret >= count)
> +       p = seprintf(p, e, "\n");
> +       if (p == NULL)
>                 goto err;
>
> +       ret = p - kbuf;
>         if (copy_to_user(buf, kbuf, ret))
>                 ret = -EFAULT;
>
> diff --git a/mm/slub.c b/mm/slub.c
> index be8b09e09d30..b67c6ca0d0f7 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -7451,6 +7451,7 @@ static char *create_unique_id(struct kmem_cache *s)
>  {
>         char *name = kmalloc(ID_STR_LENGTH, GFP_KERNEL);
>         char *p = name;
> +       char *e = name + ID_STR_LENGTH;
>
>         if (!name)
>                 return ERR_PTR(-ENOMEM);
> @@ -7475,9 +7476,9 @@ static char *create_unique_id(struct kmem_cache *s)
>                 *p++ = 'A';
>         if (p != name + 1)
>                 *p++ = '-';
> -       p += snprintf(p, ID_STR_LENGTH - (p - name), "%07u", s->size);
> +       p = seprintf(p, e, "%07u", s->size);
>
> -       if (WARN_ON(p > name + ID_STR_LENGTH - 1)) {
> +       if (WARN_ON(p == NULL)) {
>                 kfree(name);
>                 return ERR_PTR(-EINVAL);
>         }
> --
> 2.50.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9%3D1T-nw%40mail.gmail.com.
