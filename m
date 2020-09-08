Return-Path: <kasan-dev+bncBD22BAF5REGBBQWS335AKGQEG7OEMXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 90C6C2613E0
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 17:54:43 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id s141sf9407938qka.13
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 08:54:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599580482; cv=pass;
        d=google.com; s=arc-20160816;
        b=oqGiCw4hL0/CPRtIDDmeyYneWmVI0bUCTIOSOpt2h4JJIOPgUUGyUXbUtvvsgYECP/
         W3uiL0prTEeluQCyJxcFlb6AoUp9QqcSXVaCyCCj82iQnTHCmWd0dkN3wrtFfn+OPajZ
         3eqowzkEFyBc/EdFOVgFPp1yzcIxDn2tJo2eiD0kj81JWLxnmDuXJAOSZu1nYZKsfi2L
         8+SDnxeRYqSJciK0E5u/Kufn+s4OPUSyCASqVVUEW/9OvCymnVofRROgmTDFvFkGPESM
         9CWSrI1YvZhovvvvLxAHlcYfhKxek2hy0FPkhZzcDc80cnjY6Dflq6I1c4HG9TwB+Dkn
         z+fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=stC3ht/uY/Lz+46DHhLHlNTL1kzCTpoKHrbyohyxhU0=;
        b=SIh2KV16VwWL9U+dMyLHJVtAXEMBI51IQEBLRinvUCWIzPCYpQXukx9y5eyWKq1iS6
         B1/DDW2Wccz+RavHcOL/gvL9PGivT9xWjjWGqBw+NQhc7hbyxqPgL7MiKqj9EpIqDO5n
         Hfv9gGOk/rxvUCz10YR1lchoVugoraixXqPnRVPFB7MSRcKLz6l52fLlfwfZuQiD5MpN
         SRcv5FeYV26qJ/wVog6BWvddlfwYZSnHlqm0GeCtTJCMweov0e8VQK+sqYF1Jk3rG+UM
         kOeCfH18xwexPQNH2B4lbJ0nmmCBWrbXWavobnxLzUxQ8U1m9xmmQ634OgWZjdDKtxob
         F2Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=stC3ht/uY/Lz+46DHhLHlNTL1kzCTpoKHrbyohyxhU0=;
        b=Coc+zSFK6DvJ6YGLqpPIkNRRESq/HECHNZDxWCxv/Uduh3eaPH6PYmwsKMAQgN1DUU
         XqmY8et9e5xxeQzyhIMUBWgb50wtxgWlBBdB2mxX39/KshFdDo6NWFWvIG1id/iBtZ4w
         6WQ+4N/qAJuPT88l7aSOYnjpt4gXysspC/1QiD3nUcMMu+h91OTwDNGAnjbDZ75gxdRg
         g8yWu2kTzWaGYqQATQWe1YpPv6AOrqoJe+gII9EFSTrce/rFYSFnOxRKiuNxWqtstHTS
         jLSXHelKqQpKp7fPZpm03wrRBLKwPxfU5cQj41IdAgWqm+5SDAJqrg2SUi656I4GmrDW
         69jQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:subject:to:cc
         :references:from:autocrypt:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=stC3ht/uY/Lz+46DHhLHlNTL1kzCTpoKHrbyohyxhU0=;
        b=X+vw+T3n8NBB8ZkKTLT6Rlj9+wgbh/FbpR/OrwE/7lkYWIohBuUNR8JSxOX5zCt9j3
         St9ByL3dvRHWC8vpfePrdPxLPKgVJASYXLqIwvHlj1WnRmqhS5z7G+lpci/BxKxohB4R
         fWj2S+u44qltt6KFflM48tOgOMgMXuvTCgaW00cDJWDGGNODo94hPTjW+dub4adJ7C/0
         8JhVSy4NWOCJA5kYW4e6Ho7DGvlJlTLK1AB7mSfjidf/wx6hKiARovFIsAnnWYgWk3fZ
         xnmgH+THHzkbhW0ovBvgJ+HjRdEL1cXhruw2wDUBZbBSAd7B7VhCoTYb7LroKE70a3S3
         8mUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Oe7mY89r9Yes9BDiMVM+Iw/mKgu2Qsd2nMnCZkvlPgssdfqRN
	DGDyKECWnVG5LtEcEzYyuc8=
X-Google-Smtp-Source: ABdhPJwPPH16UU/HoSfqZbQkRbm0J9ViRTU9qnRAW5veFSK/XJBfRnT1Vd6uXxfixo7dHZZr0uzUkw==
X-Received: by 2002:a37:b307:: with SMTP id c7mr695311qkf.33.1599580482638;
        Tue, 08 Sep 2020 08:54:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2a65:: with SMTP id k34ls7901847qtf.5.gmail; Tue, 08 Sep
 2020 08:54:42 -0700 (PDT)
X-Received: by 2002:aed:364a:: with SMTP id e68mr726929qtb.260.1599580481787;
        Tue, 08 Sep 2020 08:54:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599580481; cv=none;
        d=google.com; s=arc-20160816;
        b=lW+EuDPuYgWnwwzCU1j8X57xw2wmHNNw2XlxG+LKBPs2mxkuoneDCVgd8U9WeOv202
         sycF/iLQoLQKWK7Hhahnw9Mw4VzOUHzHDPbmayjvpIdQ9A3+PUPAbc+gH2oe6p8g1IfO
         X0rXSYfWwOo78cJFTzWJKCcJtfTA2K84zfvaqw/7WJxXE0mAIzSoDEATZ5JF52ZBj2F/
         Upo1b1OJkeMNNKtvMhXbyNumlXjJ9C5Izs22AcGu7LFSFMhbL+YFLJMkCz1BObWy+akt
         lDeYb8axe+sy4lVq3sMoRAEXZylMn/AlI89B5QTqFanCzOzi6MzCfuMg3+q0M6k8lZRU
         wCyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:ironport-sdr;
        bh=kdrhrxGc+1Q2giHwgdA2OyCuTjwXkWs8SXC6QXN5HZY=;
        b=qOQM+QbHV214HmYkjG0B2UtubX5QyhUMrJ4aOWZgWA20THLYRfEIf/jqVtjSDk3PIV
         z4etPnO7PJ8Nk0xT0QHi34n9e9W9YcrHf7sM8TtIzyVkoolhrNbSPHG+buewU6j+kvUB
         ZfOiUFDQfKig1SJmQS7tWNXc/KwkQrKUaL+TEazmqpZMJF7QpCJegplpE1e9/zxEzpSd
         iUkXRUWeWugiOX3m8RI23AXiQ1yfMoTR6W56Ynov/H6q8YRLhmWLwigJTZN101UgtVQX
         wSJZ7ow63zkNjmGRhX0gk8r+VKuYVtAlupF6Hi98F/oGsyf1VSUuvTN2xQP80RZXoEe+
         Hsqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id l38si926389qta.5.2020.09.08.08.54.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 08:54:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
IronPort-SDR: Mp7tcRIcSTnYhDBXOh30HYwg1mo+nNkQRT8g4N/PcJ03PyRWK4WEfbBQ6X0TCF9GIe0eQXeWYo
 3pY0N6xKt5uQ==
X-IronPort-AV: E=McAfee;i="6000,8403,9738"; a="155562521"
X-IronPort-AV: E=Sophos;i="5.76,406,1592895600"; 
   d="scan'208";a="155562521"
X-Amp-Result: SKIPPED(no attachment in message)
X-Amp-File-Uploaded: False
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2020 08:54:39 -0700
IronPort-SDR: T/1nXKokDV2anso0ibUdaFY4IRwHXk4XDbsdwwQVHcDxggXBHCGPbD47sN0fpoKWjY0Q8JfeEW
 7rW0V0zEO1TQ==
X-IronPort-AV: E=Sophos;i="5.76,406,1592895600"; 
   d="scan'208";a="299836594"
Received: from sparasa-mobl1.amr.corp.intel.com (HELO [10.251.10.231]) ([10.251.10.231])
  by orsmga003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2020 08:54:38 -0700
Subject: Re: [PATCH RFC 09/10] kfence, Documentation: add KFENCE documentation
To: Marco Elver <elver@google.com>, glider@google.com,
 akpm@linux-foundation.org, catalin.marinas@arm.com, cl@linux.com,
 rientjes@google.com, iamjoonsoo.kim@lge.com, mark.rutland@arm.com,
 penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com,
 aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de,
 dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com,
 gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com,
 corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw,
 tglx@linutronix.de, will@kernel.org, x86@kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org
References: <20200907134055.2878499-1-elver@google.com>
 <20200907134055.2878499-10-elver@google.com>
From: Dave Hansen <dave.hansen@intel.com>
Autocrypt: addr=dave.hansen@intel.com; keydata=
 xsFNBE6HMP0BEADIMA3XYkQfF3dwHlj58Yjsc4E5y5G67cfbt8dvaUq2fx1lR0K9h1bOI6fC
 oAiUXvGAOxPDsB/P6UEOISPpLl5IuYsSwAeZGkdQ5g6m1xq7AlDJQZddhr/1DC/nMVa/2BoY
 2UnKuZuSBu7lgOE193+7Uks3416N2hTkyKUSNkduyoZ9F5twiBhxPJwPtn/wnch6n5RsoXsb
 ygOEDxLEsSk/7eyFycjE+btUtAWZtx+HseyaGfqkZK0Z9bT1lsaHecmB203xShwCPT49Blxz
 VOab8668QpaEOdLGhtvrVYVK7x4skyT3nGWcgDCl5/Vp3TWA4K+IofwvXzX2ON/Mj7aQwf5W
 iC+3nWC7q0uxKwwsddJ0Nu+dpA/UORQWa1NiAftEoSpk5+nUUi0WE+5DRm0H+TXKBWMGNCFn
 c6+EKg5zQaa8KqymHcOrSXNPmzJuXvDQ8uj2J8XuzCZfK4uy1+YdIr0yyEMI7mdh4KX50LO1
 pmowEqDh7dLShTOif/7UtQYrzYq9cPnjU2ZW4qd5Qz2joSGTG9eCXLz5PRe5SqHxv6ljk8mb
 ApNuY7bOXO/A7T2j5RwXIlcmssqIjBcxsRRoIbpCwWWGjkYjzYCjgsNFL6rt4OL11OUF37wL
 QcTl7fbCGv53KfKPdYD5hcbguLKi/aCccJK18ZwNjFhqr4MliQARAQABzShEYXZpZCBDaHJp
 c3RvcGhlciBIYW5zZW4gPGRhdmVAc3I3MS5uZXQ+wsF7BBMBAgAlAhsDBgsJCAcDAgYVCAIJ
 CgsEFgIDAQIeAQIXgAUCTo3k0QIZAQAKCRBoNZUwcMmSsMO2D/421Xg8pimb9mPzM5N7khT0
 2MCnaGssU1T59YPE25kYdx2HntwdO0JA27Wn9xx5zYijOe6B21ufrvsyv42auCO85+oFJWfE
 K2R/IpLle09GDx5tcEmMAHX6KSxpHmGuJmUPibHVbfep2aCh9lKaDqQR07gXXWK5/yU1Dx0r
 VVFRaHTasp9fZ9AmY4K9/BSA3VkQ8v3OrxNty3OdsrmTTzO91YszpdbjjEFZK53zXy6tUD2d
 e1i0kBBS6NLAAsqEtneplz88T/v7MpLmpY30N9gQU3QyRC50jJ7LU9RazMjUQY1WohVsR56d
 ORqFxS8ChhyJs7BI34vQusYHDTp6PnZHUppb9WIzjeWlC7Jc8lSBDlEWodmqQQgp5+6AfhTD
 kDv1a+W5+ncq+Uo63WHRiCPuyt4di4/0zo28RVcjtzlGBZtmz2EIC3vUfmoZbO/Gn6EKbYAn
 rzz3iU/JWV8DwQ+sZSGu0HmvYMt6t5SmqWQo/hyHtA7uF5Wxtu1lCgolSQw4t49ZuOyOnQi5
 f8R3nE7lpVCSF1TT+h8kMvFPv3VG7KunyjHr3sEptYxQs4VRxqeirSuyBv1TyxT+LdTm6j4a
 mulOWf+YtFRAgIYyyN5YOepDEBv4LUM8Tz98lZiNMlFyRMNrsLV6Pv6SxhrMxbT6TNVS5D+6
 UorTLotDZKp5+M7BTQRUY85qARAAsgMW71BIXRgxjYNCYQ3Xs8k3TfAvQRbHccky50h99TUY
 sqdULbsb3KhmY29raw1bgmyM0a4DGS1YKN7qazCDsdQlxIJp9t2YYdBKXVRzPCCsfWe1dK/q
 66UVhRPP8EGZ4CmFYuPTxqGY+dGRInxCeap/xzbKdvmPm01Iw3YFjAE4PQ4hTMr/H76KoDbD
 cq62U50oKC83ca/PRRh2QqEqACvIH4BR7jueAZSPEDnzwxvVgzyeuhwqHY05QRK/wsKuhq7s
 UuYtmN92Fasbxbw2tbVLZfoidklikvZAmotg0dwcFTjSRGEg0Gr3p/xBzJWNavFZZ95Rj7Et
 db0lCt0HDSY5q4GMR+SrFbH+jzUY/ZqfGdZCBqo0cdPPp58krVgtIGR+ja2Mkva6ah94/oQN
 lnCOw3udS+Eb/aRcM6detZr7XOngvxsWolBrhwTQFT9D2NH6ryAuvKd6yyAFt3/e7r+HHtkU
 kOy27D7IpjngqP+b4EumELI/NxPgIqT69PQmo9IZaI/oRaKorYnDaZrMXViqDrFdD37XELwQ
 gmLoSm2VfbOYY7fap/AhPOgOYOSqg3/Nxcapv71yoBzRRxOc4FxmZ65mn+q3rEM27yRztBW9
 AnCKIc66T2i92HqXCw6AgoBJRjBkI3QnEkPgohQkZdAb8o9WGVKpfmZKbYBo4pEAEQEAAcLB
 XwQYAQIACQUCVGPOagIbDAAKCRBoNZUwcMmSsJeCEACCh7P/aaOLKWQxcnw47p4phIVR6pVL
 e4IEdR7Jf7ZL00s3vKSNT+nRqdl1ugJx9Ymsp8kXKMk9GSfmZpuMQB9c6io1qZc6nW/3TtvK
 pNGz7KPPtaDzvKA4S5tfrWPnDr7n15AU5vsIZvgMjU42gkbemkjJwP0B1RkifIK60yQqAAlT
 YZ14P0dIPdIPIlfEPiAWcg5BtLQU4Wg3cNQdpWrCJ1E3m/RIlXy/2Y3YOVVohfSy+4kvvYU3
 lXUdPb04UPw4VWwjcVZPg7cgR7Izion61bGHqVqURgSALt2yvHl7cr68NYoFkzbNsGsye9ft
 M9ozM23JSgMkRylPSXTeh5JIK9pz2+etco3AfLCKtaRVysjvpysukmWMTrx8QnI5Nn5MOlJj
 1Ov4/50JY9pXzgIDVSrgy6LYSMc4vKZ3QfCY7ipLRORyalFDF3j5AGCMRENJjHPD6O7bl3Xo
 4DzMID+8eucbXxKiNEbs21IqBZbbKdY1GkcEGTE7AnkA3Y6YB7I/j9mQ3hCgm5muJuhM/2Fr
 OPsw5tV/LmQ5GXH0JQ/TZXWygyRFyyI2FqNTx4WHqUn3yFj8rwTAU1tluRUYyeLy0ayUlKBH
 ybj0N71vWO936MqP6haFERzuPAIpxj2ezwu0xb1GjTk4ynna6h5GjnKgdfOWoRtoWndMZxbA
 z5cecg==
Message-ID: <3e87490e-3145-da2e-4190-176017d0e099@intel.com>
Date: Tue, 8 Sep 2020 08:54:36 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200907134055.2878499-10-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 9/7/20 6:40 AM, Marco Elver wrote:
> +The most important parameter is KFENCE's sample interval, which can be set via
> +the kernel boot parameter ``kfence.sample_interval`` in milliseconds. The
> +sample interval determines the frequency with which heap allocations will be
> +guarded by KFENCE. The default is configurable via the Kconfig option
> +``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=0``
> +disables KFENCE.
> +
> +With the Kconfig option ``CONFIG_KFENCE_NUM_OBJECTS`` (default 255), the number
> +of available guarded objects can be controlled. Each object requires 2 pages,
> +one for the object itself and the other one used as a guard page; object pages
> +are interleaved with guard pages, and every object page is therefore surrounded
> +by two guard pages.

Is it hard to make these both tunable at runtime?

It would be nice if I hit a KFENCE error on a system to bump up the
number of objects and turn up the frequency of guarded objects to try to
hit it again.  That would be a really nice feature for development
environments.

It would also be nice to have a counter somewhere (/proc/vmstat?) to
explicitly say how many pages are currently being used.

I didn't mention it elsewhere, but this work looks really nice.  It has
very little impact on the core kernel and looks like a very nice tool to
have in the toolbox.  I don't see any major reasons we wouldn't want to
merge after our typical bikeshedding. :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3e87490e-3145-da2e-4190-176017d0e099%40intel.com.
