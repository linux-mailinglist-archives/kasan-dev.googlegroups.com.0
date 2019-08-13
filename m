Return-Path: <kasan-dev+bncBDTN7QVI5AKBBY4ZZXVAKGQEFMLCVBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AB7A8C4E7
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 01:51:01 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id j12sf63708306pll.14
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2019 16:51:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565740260; cv=pass;
        d=google.com; s=arc-20160816;
        b=nyHXFyuc8qUhsnzixmr4ifVqO99mJdB/Db9/k8noWz2i11wI3ql5aZdA2HMcCa/lQt
         x0nQKMl/Tyz3zYxLVyOCFhEd3TuAeVhxb5osl+ubIIYB/b5ygenKMdc+Gn5Wwj162kiW
         0h2veLDcTVPxTthh2pzfSU7hG6UcQo5WARvNvehExuFkskOfKDHgHT357cYbkI/fe+d3
         OivOmgwQ/FKRhJw7a5Kyyt7J7TDdTh/BESTQWTaZMCBSts/CmvTIJ0GPSBtkvPlds66m
         Bh6wPmhqm6RhYz237dyl5bFCn7oL4r4QAX9wXBjIUNOtPeNayYDD7sJ/mwQRiHdNpebp
         S69A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=62QENJ00aIzxI4oOzHi1skt2lyHeYkmr3q61jVFwnyI=;
        b=BEHzg2qekFfdnbHh5Gjx/C/SjuLzIRfiDaGv8UbPAs0mhhH87156TnAu3L+BNVfNjW
         8ZG9LmdRSDE4jlLB0Xz7WfZNrC1GWWdSRJ8+UlEjoZQXMiFKBuYXV77cjzWqVe1v/ccv
         Hb2e3V5T2GSVYmEbmI59UDGHGGHlWBqzjadgmEk9a7bcSsaerEjqG6RukAhQW3GXAlbn
         j9BQXJ/JqJXlFoAF4PVcf0m63qV6MtAN1kD16ln0ID2D5IwUEMS8UGgBjvbscqfvP5ZY
         w53z4znWwNoEKBxSP45nfjssI95ld5h0Nb1vCtGygVj1CsiScCTHlLMB+NH42sUmuRml
         5nnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 209.85.210.193 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=62QENJ00aIzxI4oOzHi1skt2lyHeYkmr3q61jVFwnyI=;
        b=od+3QLrYYQHcLTon31Li78xeG8FSTmgcS+GIaIZ7i7iL3J2jPgDuFOj4ajbI0rSoWS
         4g9DCBG5PYKqxwIITJBJ6/y4FnhjAbp3hko3ByWt01jxXWzVRCTQ/FdpyMBP3e5KyB7f
         If8Mh4wCWEuMAMnKALJk0MJ5/RHfumNFqyxPvXMsgjagBX9PcKDf3hng+GS0Ffwe1sv8
         pYc+/wu5AGNZb1bjLOO3EtBNk3PqoyDIJ7tHxlRhTlP0oBGcTVEjcZmn5LuzOwRJqjT5
         9xlHU4/6R4cC19yujVeSdKEFhX5ztIf85adDsWyh4KegIBexLd+FRJykJEVDA6U23ZHS
         ppDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=62QENJ00aIzxI4oOzHi1skt2lyHeYkmr3q61jVFwnyI=;
        b=l22A0U59CJg2eR4Gg37oQ5b4olE4D1FGflQu1jf38RhI7AwSiGMQR4RQVm5ip3uNAa
         zoVvnvKBtca5cVcSoptQqrI7HFSwwQXJIFXHataiSeNyZnKBoW1I6pmWfWqB5M68R7Ud
         l0VaGIygNjM/X5aSguAUWvW4R0+grseEpOwoMU3jq0Uuk7napSrrTcGaDkc7qSPrv8UU
         +ekYVmEfAbks4tWciWFyfVJnMAlgT7FGdlvvPV5OtJh5aY2kFcs6moz1mz+5TJ4t/Nt0
         2FEHk2/mplWo+pAx9WidVxt+ZKIZIa5JS2JpA7COdL0UXgJ6AdI3B1M/ZociSXykczen
         3xtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWhGLcDs/kBhxwXuvB/TtamP0Ey3XONZLNw4VBMd+A8oU0ort6g
	QQ/BDLNOyitU5pQvwOc1AxY=
X-Google-Smtp-Source: APXvYqwiBwivre6/aLwS9qrfDcb7gFea9LoQG3Y9KnUnDW/ySd2+IBwQHPQlVa2hPfpT6gDepTsZ7Q==
X-Received: by 2002:aa7:8edd:: with SMTP id b29mr13386510pfr.173.1565740259976;
        Tue, 13 Aug 2019 16:50:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a4c5:: with SMTP id l5ls139704pjw.5.gmail; Tue, 13
 Aug 2019 16:50:59 -0700 (PDT)
X-Received: by 2002:a17:902:9686:: with SMTP id n6mr2326479plp.113.1565740259577;
        Tue, 13 Aug 2019 16:50:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565740259; cv=none;
        d=google.com; s=arc-20160816;
        b=lSGAtd8vlGtK+I/ReV+Qma60l+kWuA2Y7qvARZnPpRXai8E/Lpm4RncvbYqSbGDjYF
         ZnIGxOTHVHYCRe0Adk61ZCltvEoyq/jxv0oyhdQJ8yO7uYk2jiMBQ/om9k6ATmwr2OLZ
         y5KahtC68uGKUNc6TUKJDOZgoak7RFwWAqJzfSEp9jrEmAdmvjkhfofQIs33L+LN5xg5
         Dh/hVDSUUvpAdknPZK65xjL5x+AB9vWABYD+h2ALGkgLRa5GEBqrunNKgiPst/7hQsgj
         YU0fdQnltFxcQA05PilE0QG+1+ZGA4t/ggSw/PEzPmCaFY8JYOskut416GrZVyyaPGgw
         WfCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date;
        bh=IbdE2KInyJodKUCtVAuZWET2xZ1Z2VbKwChNL5TWr0E=;
        b=Z0F6T7+A84cwGtw202VCSmXLqfHv30ylp+kLBk3YyBcCl57GiTcFsDpb2bdqzZUeXB
         pV+M3NhkW18tCR2Zqpm2xEme3cxAEQ2zx8Z45+uF8XwBh+j5Meh5dSnujwWpzUkTcrSE
         t/8Kq3fURYN6Ib4UOs1qdT2DrWYsJVtTub4NiPa6dJrp/yUgsGj4MUjJyFI0m039AdvL
         kF9ta2UmG0+GWCWPkmz6YTjlhEYnIpqNbUtwaad63Ubu1Mv4aaYrBzGPBPXUA2TGbXpA
         MjDZPXoS991qT337MlTzhN4taeuZ1mLv3mJq4B0Ym3ZrxzSaxHzx0ElXeKGZIta2jA/V
         0vPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 209.85.210.193 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-f193.google.com (mail-pf1-f193.google.com. [209.85.210.193])
        by gmr-mx.google.com with ESMTPS id i184si4111232pge.5.2019.08.13.16.50.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Aug 2019 16:50:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 209.85.210.193 as permitted sender) client-ip=209.85.210.193;
Received: by mail-pf1-f193.google.com with SMTP id c81so3484184pfc.11
        for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2019 16:50:59 -0700 (PDT)
X-Received: by 2002:a17:90a:2c9:: with SMTP id d9mr274835pjd.134.1565740258768;
        Tue, 13 Aug 2019 16:50:58 -0700 (PDT)
Received: from localhost ([12.206.222.5])
        by smtp.gmail.com with ESMTPSA id 81sm163022302pfx.111.2019.08.13.16.50.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Aug 2019 16:50:58 -0700 (PDT)
Date: Tue, 13 Aug 2019 16:50:58 -0700 (PDT)
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
In-Reply-To: <20190812150446.GI26897@infradead.org>
CC: nickhu@andestech.com, alankao@andestech.com,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, green.hu@gmail.com, deanbo422@gmail.com,
  tglx@linutronix.de, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com, Anup Patel <Anup.Patel@wdc.com>,
  Greg KH <gregkh@linuxfoundation.org>, alexios.zavras@intel.com, Atish Patra <Atish.Patra@wdc.com>,
  zong@andestech.com, kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@sifive.com>
To: Christoph Hellwig <hch@infradead.org>
Message-ID: <mhng-ba92c635-7087-4783-baa5-2a111e0e2710@palmer-si-x1e>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of palmer@dabbelt.com designates 209.85.210.193 as
 permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 12 Aug 2019 08:04:46 PDT (-0700), Christoph Hellwig wrote:
> On Wed, Aug 07, 2019 at 03:19:14PM +0800, Nick Hu wrote:
>> There are some features which need this string operation for compilation,
>> like KASAN. So the purpose of this porting is for the features like KASAN
>> which cannot be compiled without it.
>>
>> KASAN's string operations would replace the original string operations and
>> call for the architecture defined string operations. Since we don't have
>> this in current kernel, this patch provides the implementation.
>>
>> This porting refers to the 'arch/nds32/lib/memmove.S'.
>
> This looks sensible to me, although my stringop asm is rather rusty,
> so just an ack and not a real review-by:
>
> Acked-by: Christoph Hellwig <hch@lst.de>

FWIW, we just write this in C everywhere else and rely on the compiler to 
unroll the loops.  I always prefer C to assembly when possible, so I'd prefer 
if we just adopt the string code from newlib.  We have a RISC-V-specific memcpy 
in there, but just use the generic memmove.

Maybe the best bet here would be to adopt the newlib memcpy/memmove as generic 
Linux functions?  They're both in C so they should be fine, and they both look 
faster than what's in lib/string.c.  Then everyone would benefit and we don't 
need this tricky RISC-V assembly.  Also, from the look of it the newlib code is 
faster because the inner loop is unrolled.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-ba92c635-7087-4783-baa5-2a111e0e2710%40palmer-si-x1e.
