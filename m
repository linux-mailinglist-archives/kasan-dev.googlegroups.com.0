Return-Path: <kasan-dev+bncBCT4XGV33UIBBIOWTOAQMGQEBSJ6ROI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 0458231A63E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 21:54:59 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id h18sf382671otg.22
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 12:54:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613163298; cv=pass;
        d=google.com; s=arc-20160816;
        b=zDgvwFCLEce0OV8S8MYIRtSvTPY8Krr/DnaqG2+GzPOGgbPBoJ9+YmeJH67Q1ukuDU
         Prb22kDdpfT0z2NwupVjf5lR3bDtl4rC8ZqgxILZhmmO8gtH0uhmZEe3uih86U/yvusT
         dzcFSPzrxJ+st3xT7sxXbn2rLcq9x/dKjPz+MlG58K6B1ARENdJOe1KufBF0zREsBABv
         o31G1YKotJJc8QSnhYmulhDhBIfWJQJvtah3TFo2ioi6Sl8NuL6IGoMugkR2cepJMuQX
         Mrj8AwI2NidYt8jG/W0CWNvr52Um3JmkdHZc9GsO8O5ONgyqpFoO7Tnz8ngAY4gh/NJe
         86hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DlrkxRxgkI0hj9dzsPU1BrQY73YOQlFOy6A3POddwYk=;
        b=nt7T3PujMQijcqQnHUXNGmmkXrGTeLgzIf07M2AwcneCxP7qAD6FGleXxqv7Uc8uzX
         hr2YdaH47MonEXWT1aff3IB7VAEIwCZWVUicvB2rmAsvCdLkW4ZzKv/CZ35VKVCu0iGC
         Yi8Zsv0OY41GxXsf23liYgjfOvrW2nsljvBwj1wJjSQClVgmw46lXMR3qchTSMKhF5aD
         YVDLw9Dk4r52RseODDSO4hdSvsKObuPJlzgsW7F0Zun4td5bVXAlIODjPvehdf0md+Ci
         hiKv5oU9/3s1nPDT7WY/RodufhMsqZG2W7XHbAnHITV0mz5/Z8GnHfwl3xPu/29NLuc5
         EZvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=MXmSU8z6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DlrkxRxgkI0hj9dzsPU1BrQY73YOQlFOy6A3POddwYk=;
        b=BP163NFd3zIDmib2wm7C7hFejQ8scDBwT6bWCHNj+QvUTP2fbbyNStmxGdxYJR7NYJ
         YCNRdoo+UqqcUoW8KCJtJdpgFAU0Zy1o7GesJydLeP4wFK1is26WMZQjPGgE3rnBC9HK
         e2qN5GgbB6GCWkqUKensAj5Oolkl2nEoxxFApsgN/oSxWANct7Xpt3gQ28RQrzruAnMo
         6LqTCbV6GUFisR0/+W+G5dzh6/1ybTCput8nS/hqdgMqLG+GXbIJS9yhlmihhczC9Ijt
         KcQsF9crnGU9NVK9T8a8GRqAlAo2/6yMyuOqL1u4bm6FKRdmgE1GcBvoNUac4Jg71GGF
         AesQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DlrkxRxgkI0hj9dzsPU1BrQY73YOQlFOy6A3POddwYk=;
        b=o9S36vL7FA5E3ROPJL3UDqqpEROV2yH8nuBurqnF0cmlrgqx9zKiyRyOcId4h+ssVy
         sZqdb9EoShHi6EusiBvS58lWnbFx8zJfZ7OTYKthuiH8TPiFuQzbaBZeHEkNi+zJEyji
         c4ga4fnhSFbHAfboZQXWvVKukrpsLzL3FLQquzQfmG+6PZyWrUXNjuJwnbHM9F18Q91t
         1oISkwqDPlXHEGMC2wbDfEfAhFXt1DmL1hTm0JURLyj4HMz0n40KfhuRF7iKNeJsP38P
         XSUGJqPDRZAuLq4klIdBZIo1BCUgzGqYShOkQxixAzqlBq3aeTVY28aSpZbDrqr1D52t
         oMSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ftoj4iwY3ZAzWXCg23eXOBwDOw8HXh/DcafZu0gVEBv4kWZGS
	hd7j41WkEm/xODPzCm5F0Gs=
X-Google-Smtp-Source: ABdhPJz0zJ2F3D40Fz3LFpOQXKhwGJ97vsSrTe+4418OK3VErcJM1S7gdVr2Y8mGfhh0Drk8xhrvDA==
X-Received: by 2002:aca:6509:: with SMTP id m9mr959622oim.35.1613163298014;
        Fri, 12 Feb 2021 12:54:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3407:: with SMTP id v7ls2393868otb.9.gmail; Fri, 12 Feb
 2021 12:54:57 -0800 (PST)
X-Received: by 2002:a9d:8f2:: with SMTP id 105mr3368171otf.64.1613163297487;
        Fri, 12 Feb 2021 12:54:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613163297; cv=none;
        d=google.com; s=arc-20160816;
        b=FZlnmocB4F9/WMc2yU74nNsEcvbo22D8YRzD4ZVnSIgiLJ4t5Lz+AE9V4/KZxYqhm1
         ck6VaRBtre1YyzhVapJSUXbmfEXI0k4NA89cHc/qRT3ojWGwUnxWtbCGfKJ7knvZ54Ux
         FPE7+5XvPeigO9k6lBQxs5ZF+z64xD8dfALNlHiW9Rh7RxmuIb1Jhwd3aq60Dhp8Yl8y
         Rkz3LZuW2opw/4b3kYYTCuNfnJa7klNdgf/81TGqE340I/ImtCJuWBYbZRwUGb5YWXdk
         aOigX2Y+K373ldDTli9wqwTy9Svo51dZSV6HsJg8k5mb8gRIg+Qcb7wZSCC5PkVat7HL
         9igw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=FyGMWhRfBCGn0+zNdUQg2ua4kivwCVJ/S1cL1pIw0l0=;
        b=PbGyVtyUu3Y37msgDwoTLwI5FIS94jElHgehpxzGY9nkxq60kWy3RVggN70O0AAh87
         0Y8VleJsELkrcF+jgbquWnGP+GXEl97VJdndHGBAfJ89lsNwlWl8AXCWwQqH7EoQ231h
         GMTxGcFv9dOrQYgjnAcUd6MGr9ppEtYc6CeM9WhyLTmROtnJ/MS6JIGfL/VO9aIy4q/B
         Dn0T5+NblKuIew1lq3/z2XhkTrIKM1Ns3SqGarnasFTNKUxUOIlCrMWwLarOIi7O0iA6
         JZCp2vaZ0DGRlGxs8CBI8LUE9JOSm6JkKttktnE5M6AJK7SCBrCt4aZPvj7kMhrRT5dQ
         VsoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=MXmSU8z6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y189si884406oia.4.2021.02.12.12.54.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 12:54:57 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4E1EF64DEC;
	Fri, 12 Feb 2021 20:54:56 +0000 (UTC)
Date: Fri, 12 Feb 2021 12:54:54 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, Will Deacon <will.deacon@arm.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov
 <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, Kevin
 Brodsky <kevin.brodsky@arm.com>, Christoph Hellwig <hch@infradead.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, Linux Memory Management List
 <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH mm] kasan: export HW_TAGS symbols for KUnit tests
Message-Id: <20210212125454.b660a3bf3e9945515f530066@linux-foundation.org>
In-Reply-To: <CAAeHK+z5pkZkuNbqbAOSN_j34UhohRPhnu=EW-_PtZ88hdNjpA@mail.gmail.com>
References: <e7eeb252da408b08f0c81b950a55fb852f92000b.1613155970.git.andreyknvl@google.com>
	<20210212121610.ff05a7bb37f97caef97dc924@linux-foundation.org>
	<CAAeHK+z5pkZkuNbqbAOSN_j34UhohRPhnu=EW-_PtZ88hdNjpA@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=MXmSU8z6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 12 Feb 2021 21:21:39 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> > > The wrappers aren't defined when tests aren't enabled to avoid misuse.
> > > The mte_() functions aren't exported directly to avoid having low-level
> > > KASAN ifdefs in the arch code.
> > >
> >
> > Please confirm that this is applicable to current Linus mainline?
> 
> It's not applicable. KUnit tests for HW_TAGS aren't supported there,
> the patches for that are in mm only. So no need to put it into 5.11.

So... which -mm patch does this patch fix?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212125454.b660a3bf3e9945515f530066%40linux-foundation.org.
