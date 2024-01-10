Return-Path: <kasan-dev+bncBCV4DBW44YLRBVGD7SWAMGQE5TRA6NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id F2F0082A4B4
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 00:01:42 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-28d2a727782sf3679154a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 15:01:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704927701; cv=pass;
        d=google.com; s=arc-20160816;
        b=G6rrErYsYnHQsdtPxm+IHYumvKlSTtXh/yzUbJMh+Go7l+yciuN6TmgsmrJruT5Xy8
         bk+D7EEZTPXRmP5Gje/vnDSfHxcmnOsgKz7NZIqGv7adNF3t5slJQxmq5hF1KRRG29vb
         CJkZXJPJ+Cnl++Iyv6ixPhgP1fLfEbSmrGuDAtYkzxPNusovCQeu82P9KupB2JkPGN6A
         W+IP+0IzOPAaROquBYHYudx1NbUwR69FgHLOxFYzjBBjHUzPzpUKrZAE/8iztVWa/cNO
         KPegoe1K3tS/RctuyKdb1DU1ph/kwJ8g7TWJ+MkARkl+kJYXRUf02Ls2NuJNzCVrxURK
         af+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender
         :dkim-signature;
        bh=8rfuhN25/fTRgGsuzwHH7lvxT2qG1tP95bcHWugDudI=;
        fh=nWr82wMEO9GKNdR/jfN+lbsaiqRsw6PK5qZUzVcrvhM=;
        b=MI2VB4DYfJRL/xcF/LrOk1uyJfK/C+IN4TZhB/Y4VD+0jvsIv6tjx8WpJBiDVGH2kU
         rGoPQfZKL7e24Tjp8hbz6Ncjpwtk8CnJSppFffNy1M/wD04FECffb2tITNbYJk6L/CP6
         UrggysW3PxP3rHhAiydEJGyFGw0hB5oZB5sAUtdrmBGuEs9u8kF6fOVwqE9BtScx2gc6
         pm4/N8n+trAfE6kVSGm2Y9Kc3Mf+ihxbsu4Uq6A0PfG30LWU353/NblWasWmZscEc4/X
         T+ZP6qlngG0g1r7ATVJgaIyY9FWgFs+Cq5HJDBZzGlx8mDOMJW2rSmLJb0qOVmlsVn6F
         XhEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ev5wzDcb;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704927701; x=1705532501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=8rfuhN25/fTRgGsuzwHH7lvxT2qG1tP95bcHWugDudI=;
        b=DJMZNdufgYLwl/BXyJ/25TaYVTmOdYrhGiimUGqK0svTgbmGP4OOSv6O9SR6Rwy3fP
         iu2sreijDRAKrwHQ47w3YomiJoGOQ6C3DnHj4BR0omh2A+VVZYjr04M6kMnOcBQo/wdw
         vNA5HUZaFSLaRUCMIsQReGkqlLsolb8ob0TGfOKwcdgaqRX+ff5BOA0BEJHTVqDI3tnU
         iKwsUyQbC4bOWp5qvYvt3DgdFcXtWjSmweWqJDfm9vN0bFbApSZMtVYdazLHfr41+zr6
         tFywyJjjP2LW4H2K2vQ8oQMU3hQikZnR4kG6RGhocydZM/FS5p/XQXo7MzDMnEzJWQLm
         20TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704927701; x=1705532501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:date:references:in-reply-to:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8rfuhN25/fTRgGsuzwHH7lvxT2qG1tP95bcHWugDudI=;
        b=B+aim6xWsS/4IJyFZlhk7vgQjTFG3TTRiUXNpWfHB0ntko0pIFxjJd1CQV+5aKmhfV
         amrtyQs6LUXm1rtzDU6KEB6UuHkk1+qwuWT3gJABe9CE0iSMDKvrgFgky83XHkdb5zYy
         hYnFPLAjOz4Wdm3v5xxERcVNpDMmyQHUomwriAT64VtOtZ002rj2BUI3BNoSdrpN7PIb
         M5NiVPRUP62MzEWQPknYIkCJ1BFLCb7ul2PPUQwvxiAECFiCi/o2plX6VTM1CVrH3fQL
         QUejOhDz0yztyOEy2IRDMVV6q67bn2vviXEq8wjMl43O/TnBo7iMpFHj8LB0FfblFBbB
         uZRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzI6mUImM5Lb/Mt9cXZdrM/688xAyLoo1IDoKKYZTNDCPCOBd6V
	5L5wZ2ec4fztXEHzlQFlMtM=
X-Google-Smtp-Source: AGHT+IGQmonQGhTuLUDzDpA5IhqPKTvd1aiiPr9KNUv/INBTvYpeD5WfBSCmGOBxCBfmnQpFQyjUVA==
X-Received: by 2002:a17:90b:3a90:b0:28b:d485:cd5d with SMTP id om16-20020a17090b3a9000b0028bd485cd5dmr1057747pjb.15.1704927701167;
        Wed, 10 Jan 2024 15:01:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2f8d:b0:28c:fa83:9220 with SMTP id
 t13-20020a17090a2f8d00b0028cfa839220ls2301385pjd.1.-pod-prod-00-us-canary;
 Wed, 10 Jan 2024 15:01:40 -0800 (PST)
X-Received: by 2002:a17:902:d352:b0:1d4:a6bc:bc0c with SMTP id l18-20020a170902d35200b001d4a6bcbc0cmr1093973plk.56.1704927700013;
        Wed, 10 Jan 2024 15:01:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704927699; cv=none;
        d=google.com; s=arc-20160816;
        b=QOjwLuq1q7z2vijsXX9nTALrNQUOYakL3Ork4i5EAEvBWjMMglhnYFhCV2+XNsvtAf
         9kkybVi0aeGb019hQM0Gdm4J0g+6Cn4neE04wCIN3f3DwP03CueCTUcpZZDucmBLExj9
         /7bbJP1hdU2Lx6kCdBvf80JMB4bCanS0goNBV7Ue1oLAUEE17yxeFtdBhmIpugRWWpLo
         zaRmkY/U08j7P3wnw5R1nS/QQp50TDhG6eZWVexyrG54xdU4Tm8OENGewnMjk9kgs/RK
         q1d9I5bcGZI0GgV7KxUo5DADWCgRvKaEQqtLFIkDL6lku13MAiKTZv/N23OPQum/YIVw
         PEzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:date:references:in-reply-to
         :subject:cc:to:from:dkim-signature;
        bh=ljYhkcLCrxeGGTJaNjy+zm06+JUi70LsYnSqB5d6LSk=;
        fh=nWr82wMEO9GKNdR/jfN+lbsaiqRsw6PK5qZUzVcrvhM=;
        b=r+/kxoGgPDmbeKY1mfXDXtngGk0iFhFb+DbrKQ1hsdoT/qXN5m1DIp5ZBKJdok9M39
         s3qdc5haxHufhCmrZloqjq0cQn6fkTT23hZ9ekYhTa0ivp6PZ2FlEp1hK7jDXurJ6LAc
         SD+E7UoJ4oNOoUHqJS7ofF8BkAJmw07baMXoY112gQFiLgFUH0KVH8pHy0DO3gYDK0fI
         7xlkc34ZGDadlCEBi9M2qnO85vlGo6FrRilswky3x8M7eYc61GMdP2LahWZ1U52VakD8
         HRR4EYj48kN/3lC60lgQ/0/9pmC/JtVkZCOA7jTbrc0VxXHgulaqkGejEYtRzc2ktGzC
         GdtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ev5wzDcb;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id a63-20020a636642000000b005cdfe3274b9si424367pgc.4.2024.01.10.15.01.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Jan 2024 15:01:39 -0800 (PST)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6600,9927,10949"; a="465067551"
X-IronPort-AV: E=Sophos;i="6.04,184,1695711600"; 
   d="scan'208";a="465067551"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Jan 2024 15:01:37 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10949"; a="925799297"
X-IronPort-AV: E=Sophos;i="6.04,184,1695711600"; 
   d="scan'208";a="925799297"
Received: from tassilo.jf.intel.com (HELO tassilo.localdomain) ([10.54.38.190])
  by fmsmga001.fm.intel.com with ESMTP; 10 Jan 2024 15:01:36 -0800
Received: by tassilo.localdomain (Postfix, from userid 1000)
	id 2636F301C53; Wed, 10 Jan 2024 15:01:36 -0800 (PST)
From: Andi Kleen <ak@linux.intel.com>
To: Oscar Salvador <osalvador@suse.de>
Cc: andrey.konovalov@linux.dev,  Andrew Morton <akpm@linux-foundation.org>,
  Andrey Konovalov <andreyknvl@gmail.com>,  Marco Elver <elver@google.com>,
  Alexander Potapenko <glider@google.com>,  Dmitry Vyukov
 <dvyukov@google.com>,  Vlastimil Babka <vbabka@suse.cz>,
  kasan-dev@googlegroups.com,  Evgenii Stepanov <eugenis@google.com>,
  linux-mm@kvack.org,  linux-kernel@vger.kernel.org,  Andrey Konovalov
 <andreyknvl@google.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
In-Reply-To: <ZZUlgs69iTTlG8Lh@localhost.localdomain> (Oscar Salvador's
	message of "Wed, 3 Jan 2024 10:14:42 +0100")
References: <cover.1700502145.git.andreyknvl@google.com>
	<9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
	<ZZUlgs69iTTlG8Lh@localhost.localdomain>
Date: Wed, 10 Jan 2024 15:01:36 -0800
Message-ID: <87sf34lrn3.fsf@linux.intel.com>
User-Agent: Gnus/5.13 (Gnus v5.13)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ak@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ev5wzDcb;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=ak@linux.intel.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Oscar Salvador <osalvador@suse.de> writes:
>> 
>> With this change, multiple users can still look up records in parallel.

That's a severe misunderstanding -- rwlocks always bounce a cache line,
so the parallelism is significantly reduced.

Normally rwlocks are only worth it if your critical region is quite long.

>> 
>> This is preparatory patch for implementing the eviction of stack records
>> from the stack depot.
>> 
>> Reviewed-by: Alexander Potapenko <glider@google.com>
>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Oscar Salvador <osalvador@suse.de>


Has anyone benchmarked this on a high core count machine? It sounds
pretty bad if every lock aquisition starts bouncing a single cache line.

Consider using RCU or similar.

-Andi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87sf34lrn3.fsf%40linux.intel.com.
