Return-Path: <kasan-dev+bncBCX55RF23MIRBONITLFQMGQEEVDFF2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 080B7D1AE62
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 19:51:39 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59b7888640dsf5842124e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 10:51:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768330298; cv=pass;
        d=google.com; s=arc-20240605;
        b=R8khx49q1umOj9jU73i6pBDEO0tPbBwyj9Iutd6VVpoZPyUhLVVZO9ssieFustFbTs
         aTnclDeDkBxEGh0NQaTh0PjgQv1wMFY88j6Cwx/sJYjTx3SEg2O8oQvFsv0VRZrjW1j8
         xGgfrdz8pTp8dIN9c09Wms/DCnHE/Daf8++7MaWaOc1fNA65o9VmHylLVQxvtW5DMx+1
         rgF9Lr6a9G2zf04ToHW4t07LhR2KjRWb/1RzJ/vR/p237MbNgmQjTrWyKAeRxra4yTkg
         YNBi6ep2QhRY7KGgo+AAH0U58QPfY20rTOb6Bb1aUbB3axSM11EIh14gQ7EOQ2EX2Uo6
         m1Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=lhr0VUu9+jdDueO7Qg90e/FxvRe2OObd1XMrhLR24sA=;
        fh=qwqssBv8XmknAmGV46WYY10aCI9mTGuvDbXQYBAbZ/s=;
        b=Y1Ng28cSm+Jl6sEUnEjuFVXKcINabuk72Dim7mH1BM7BzAW97q3ytTo6eC+A7eEQrY
         zRH3oWyLRXEO+CTon1vLaZPM9A9CjWu81cmosVm0RMQR713CNJP3+N/FoEIPQlvQjKfA
         z13TZNMTX+bfK0LkMRN/XMTH/Ml5+aoleoWsQaM+boZXMRGCuLhKuwLYM6jKRM91+rDq
         pfLyZe7T0je/I2o1yLQ6Jn5W2lxWf8l5KgRAZ5MPdCWqVnxQtYkb7KhF9DGYWfsgZiSY
         D1fu8NtqdoBVBtavZBf3Nu2liQXsXu0dTT+Kdpje0NL6P9Gpqb1OeKDcIfoqDsESypzE
         d0lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kIsn8PND;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768330298; x=1768935098; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lhr0VUu9+jdDueO7Qg90e/FxvRe2OObd1XMrhLR24sA=;
        b=UP2aAvYDAWMb+idwUWWUxBLz5kEsZqqgAsk/pym46jTQpnI4l4mRyuGaOU9QNLisBM
         K3mvVH1aY4Cs+foR0W1wqRGO7HzXoOiEqAkn7wsTZKLlQ5Vn5XmcZLZmpRBd9EW9Mb7z
         0gAsxiprL2zUlCdu5A06hFIOReK0NzM563YWHnLRU5YAAjSEPt4kH6ZXsCT1tH73gKj0
         FZ2HqgrPliSiZfNlAfgzIJgyyR/lnILIvSMKh69OuhADasKno8+C4HzqlUYMPZCoxKyW
         nSCYpSPzPuveOky6jMfJxK1ra279F9x777FbjjCHh4ilbLQwC0OEc5TiP67rub7RIWfz
         hlaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768330298; x=1768935098;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lhr0VUu9+jdDueO7Qg90e/FxvRe2OObd1XMrhLR24sA=;
        b=o8EN9kdIfQqRFwirDXFGle5ZdhAXeu7AGrlLu5+y4SZXc/K2Ihd5KyAMan7cgPrZ3B
         ytXxMJ+mNNWo80/lXfyrZUd8TnhKeAEC7n8G24SBIMpa76VCPNj1DqM6E3aWc2nBweci
         BMRYQ4uckKbUtrKSZ7ptuWPndY0K9/pcIMiYyckVlI1mp6KftK9GV2F7LuHM+GUJx6Qi
         ytAk7Rlqj6cQP+5WoZnSdgFrxQaG+fFcvgPOuBi4K4e3v3HGoFrhfRkiYHj0fd4lC28a
         P+a8yYlljJeu87xSE4JpnFpD1Zsm3Ra7r5vbxnPk5h3fvD6WFyD7xiXWt30Ke2f7EqA1
         maJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVuAPppB8v7XASHz6/jESFviKMsp4HzyU/G6UfRcXoxNVZBjQcq1+DfDsN91oQu4FFroB01aw==@lfdr.de
X-Gm-Message-State: AOJu0Ywsm8iBM6Yp8GF6PlkeDgkVfGH85Lp5X3DrkUiQhk1gugrfR1P7
	gVX+3c81fYP+vtG7Gv1GCalCgmrJ0OZHE68YwXvb0cnWEAj35haMNUU7
X-Received: by 2002:a05:651c:2121:b0:383:1978:56e6 with SMTP id 38308e7fff4ca-383607ca542mr280251fa.29.1768330297826;
        Tue, 13 Jan 2026 10:51:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FMyGLQFrsuFiIYBFyAUGrjv0DMeHp9+lRpWwMkKEWylA=="
Received: by 2002:a05:651c:25cf:20b0:37a:2deb:36f0 with SMTP id
 38308e7fff4ca-383164dde0cls11961341fa.1.-pod-prod-06-eu; Tue, 13 Jan 2026
 10:51:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWLj0FxSGTCNrL9nbb3QbHdTQ97Bz8p8ys/ZrXBhuioO0x8qQIHwUodXTTTgth9+gJ1K3UgcR3mFA0=@googlegroups.com
X-Received: by 2002:a05:651c:1148:b0:383:23f6:652e with SMTP id 38308e7fff4ca-383606c0006mr323581fa.11.1768330294826;
        Tue, 13 Jan 2026 10:51:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768330294; cv=none;
        d=google.com; s=arc-20240605;
        b=KmvzyWOHBrqjk+nNxQ3pSsLBHpcrhqL7I2BNQc4jAWQnkJfDdO679EFIq1V8K1c4ir
         lQ+pd8EaeDCeGN1FVW4rloYebESCTuJNBG0E6e+/q7zhpSNaOEvVV2c3Xpct8W3ceeIF
         Dnuz3TrCZ5hOInqhguIiMnK/+MdnOSRSVxMx9ucN9Ba24C64OBW7T4HE+bt2J16/OLG3
         CwFB5OL3r977Ko2TRqPL1ab7p5BlxUFgIISU9A5OEGU2Ao5ObzDu/EmXLnDT1HJENsv7
         C1HFNF7+NtazfV/AaLHIu037iknOiGRuN30gANmVT2HL4MvKsq+idTa4W2J9CzjefQHu
         arQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=YSyCYm4RI/yOISWqF0EpwwOCB780fUcqokCOrTMCaj4=;
        fh=CYE9hn/ntdASS1iIil31WC23jJSjr1lVNnzhuIqkccA=;
        b=XctE19smXcBEUR8+AkhqaiMOuatmcyO+RMI5D0m1FN9UqcR6DCU4EtqhzqIlzlHh5q
         V5ta1piOwo61ErzfNTbjwjw+TYybhTq39Y7ro9N4ZFIpQi8EOtKAkagncsIo0TmnUEz7
         /8Et4qGoY0h0hLzdz4ngBcR385D/dxWk9TTq1eDl/SnRFSUl+uUUhTH26DLHSn4CQ6Rs
         d34BZNdbcBKhM1tjQrcNT6EaucBaG++YqA66X+QnFGebSRCE5PuxinHKL8AISq1NfMVD
         2AsP6BdFB90KYcErAAsYU1LM0efFuZGkOB8TGLZghDK6JlXOvLKSNprh4UAT6soqRNfo
         b+JQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kIsn8PND;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [2001:41d0:1004:224b::b3])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-382ecb22dfbsi3507801fa.3.2026.01.13.10.51.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 10:51:34 -0800 (PST)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) client-ip=2001:41d0:1004:224b::b3;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Chris Mason <clm@meta.com>
Cc: Vlastimil Babka <vbabka@suse.cz>,  Andrew Morton
 <akpm@linux-foundation.org>,  Christoph Lameter <cl@gentwo.org>,  David
 Rientjes <rientjes@google.com>,  Harry Yoo <harry.yoo@oracle.com>,
  Uladzislau Rezki <urezki@gmail.com>,  "Liam R. Howlett"
 <Liam.Howlett@oracle.com>,  Suren Baghdasaryan <surenb@google.com>,
  Sebastian Andrzej Siewior <bigeasy@linutronix.de>,  Alexei Starovoitov
 <ast@kernel.org>,  linux-mm@kvack.org,  linux-kernel@vger.kernel.org,
  linux-rt-devel@lists.linux.dev,  bpf@vger.kernel.org,
  kasan-dev@googlegroups.com,  Petr Tesarik <ptesarik@suse.com>,  "Paul E .
 McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
In-Reply-To: <a4b0be3f-bb6f-42d7-9176-a2bc0dcbd3a8@meta.com> (Chris Mason's
	message of "Mon, 12 Jan 2026 09:36:25 -0500")
References: <20251024142927.780367-1-clm@meta.com>
	<28e6827e-f689-45d9-b2b5-804a8aafad2e@suse.cz>
	<9a00f5c2-7c9b-44c3-a2ac-357f46f25095@meta.com>
	<01cf95d7-4e38-43c6-80ef-c990f66f1e26@suse.cz>
	<a4b0be3f-bb6f-42d7-9176-a2bc0dcbd3a8@meta.com>
Date: Tue, 13 Jan 2026 10:51:21 -0800
Message-ID: <875x95ibx2.fsf@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=kIsn8PND;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates
 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Chris Mason <clm@meta.com> writes:

> On 1/10/26 10:41 AM, Vlastimil Babka wrote:
>> On 1/10/26 14:20, Chris Mason wrote:
>>> On 1/9/26 3:16 AM, Vlastimil Babka wrote:
>>>> On 10/24/25 16:29, Chris Mason wrote:
>>>>> On Thu, 23 Oct 2025 15:52:32 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:
>>>
>>> [ ... ]
>>>
>>>> By the way, there was another bug in this patch, causing a severe memory
>>>> leak, which the AI unfortunately didn't flag. Petr reported it during
>>>> performance testing and it took me more than a day to find it. Oh well :)
>>>>
>>>> Wonder if things got better since then perhaps, and your or Roman's tools
>>>> would find it today? :)
>>>
>>> Yes and no.  It didn't find the leak until I changed the prompt to say:
>>> "there is a leak, find it".  I'll see if I can improve things...
>> 
>> Thanks. Hmm even if it has to be done like this, it could be a substantial
>> time saver vs finding the leak myself.
>
> Finding the missing break on the first pass was tricky because claude
> consistently focused on concerns about potential NULL pointers and
> mostly ignored the loop flow control changes.
>
> I think I've fixed things by expanding the loop analysis and also
> forcing it to make a more fine grained list of changes to analyze before
> it jumps into the review.
>
> It caught the missing break 5 out of 6 times in a loop, so maybe?
> That's probably the best I can get right now for a generic review, but
> claude will almost always be more reliable with extra directions like
> "there is a leak, find it" on top of the review prompt.
>
> I've pushed out two new commits to:
> https://github.com/masoncl/review-prompts
>
> 9a44c271 CS-001.md: pay more attention to loop control flow and memory
> allocations
> 7fad3996 review-core.md: make change categories more fine grained

It helped Gemini too. With these changes even the flash-3 model caught it
from the first attempt.

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/875x95ibx2.fsf%40linux.dev.
