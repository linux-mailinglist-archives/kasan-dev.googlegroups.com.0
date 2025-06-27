Return-Path: <kasan-dev+bncBC32535MUICBB6NA7PBAMGQEFLFLP7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E0063AEBE3C
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 19:10:21 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-748f30d56d1sf1245395b3a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 10:10:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751044218; cv=pass;
        d=google.com; s=arc-20240605;
        b=ip95EQKIjfioVlxuKFO4P1tezougswGSK+BVwXAzVcoC7FvYJk9A+OZEZLp9nlJVsi
         XNS5e1TPz3j9+Ycv5gwaAYoRlXKWgE5aU12pIUMJIRtaUvG3Zhfe86rcdstB+Xj0xLkN
         Y21BYNSEghBXVAro4ljptdCdWYab+Z1I06w6T5yMk87Dd+3QW9ajJblNlWpVrOFg0qx0
         H7i1L252rEAC8VwtR0p0K9JXrCvDdcOjb7tcL0Y3h2cnq9ndxHq822S6ksXpRb87V5Xd
         lwGvOiaPonxDMGu3X6QqUQaTc+pVnN00YW4J0H7EezHKODxfMjIcO4YDvh4gIo58NYEb
         FxIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=GexnCn/fEpiUjfIAEIgdskqf47op/V8RrVkNsDfYUIY=;
        fh=PRdRj5nFXE3qsXZaPDLOheyIqpU0iqNATimmdiFJCfU=;
        b=TORDJxDErlrnguy8fu0FgVYWcerNXf/C3CFNw2/Gl1m7ql2JbnM6UIemVLRY8jGGGu
         p9RUSEe5LMqBmTnsUiYiNKGfAZw0rLf1M3fSm8Fo/G7ui48OLVnsdrbwk3TMqWihCCPE
         klPOeF5mxMO8rfKkv4a4OhGUeqAEcC97UGWhl9a1kEMgHp3sePUxRWvHdgHmGL+0WDTR
         634v+h2VPBUIg+VE8kwP4hzbVh8wyRtmaeG+SSi4y+WDwdLANNpIS/DB8L/DFH3HIoOl
         Kfmqg3Iq/MO2W7qdvgZ9zFFg6+cd3UrDKKRMyKd7uKUqgFhh0tdSd4/c9sIPsNcDz6aE
         VI5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZSVh4MWm;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751044218; x=1751649018; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GexnCn/fEpiUjfIAEIgdskqf47op/V8RrVkNsDfYUIY=;
        b=sMqJb1eMkrChUksmldfZu6HIZD4igqF5divUR2RTpHkpH3ShYw8iqa8XfVFnpcbj0I
         4+6CEvCYM4/HJfGqWiwMU8H3L6H1osIoMX9InQgN3qFUlL/j3xyowUmapMkIPK7DpA6z
         CuO+tJs0l77G6TFjmrYFQbSI7XYQruRPtedzhTEbS01iVdPMVD5ihZ8HaZm1hqbkhVgv
         yWCFKarL6v/uhdvQqgpv9357g4t42JpxXb0g3dGLpWWhp+TgbIgcqlMEauZMRbH4BZrP
         hLI1SNgZ3LCfIQn6QBJKVTbb2tDsJ8FlGIsmv0rgUhFPXAn/zAcmCY90zp/cw4tcqKqo
         /Fog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751044218; x=1751649018;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=GexnCn/fEpiUjfIAEIgdskqf47op/V8RrVkNsDfYUIY=;
        b=cqOCYVrsF2x7VsARjS9gY6I8IRsf5iD9VO3BYfIko56mavwUHSD65c1EedxQkWdqNP
         0AKvFndEE4Tc/eNAz0n6pbWSXmqQsH5feNJH3ilDx2zjLkImveQi97yr+lEAzInxnHGD
         n0FAVMmmL+9benlO9/mOyaYhOudEOCULiJEgpyN8LLSZmfP3dMiH5aCPHnRI4g3qakUD
         ObVHkDClVuZqn4bR7dZAp3G94/syQS+d7qCggUODwR8FJj0DuWmfx5FgK482l65+LyU3
         2aMinpMoWB22Osy23p9N3qYX3D7l5iQiICcnvKVy8B+mJDvzNi8dm0dbIOQZ9UikB4ym
         PpTw==
X-Forwarded-Encrypted: i=2; AJvYcCWpKGLBj/nneeltyxG8+MR58f7igFPfWGJp101gS3Cj5b3mj8cOLteb4H0WbNucuvSPJ4Edhw==@lfdr.de
X-Gm-Message-State: AOJu0Yz4K87JTgY0XBGf3nYc9jcW0+/FEC+mhsmcfVPnESZqBTJvWa8Y
	JDzdbfc+5oO6dcuuCEhp91fdNwVvd9e1GRBqgNKO6mbo7s05Akq7c1KM
X-Google-Smtp-Source: AGHT+IHadvR3d+YNDL50z0xplbtV2+tq9zbe+vEpTHGPNcLxjfbufHjq1fQ4yckuN/7QIAdKJJDubw==
X-Received: by 2002:a17:903:2a87:b0:234:cf24:3be8 with SMTP id d9443c01a7336-23ac45e3721mr71843585ad.28.1751044217472;
        Fri, 27 Jun 2025 10:10:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZduvAqlczyV1TyzQ2G8buAVJ3rHDWaOK8gz8qZcdjsshA==
Received: by 2002:a17:902:c950:b0:234:b428:baa0 with SMTP id
 d9443c01a7336-238a8199ffdls24583705ad.2.-pod-prod-01-us; Fri, 27 Jun 2025
 10:10:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHnSYykR07AKqAQSlF+qlhkaGMRFPprlN+nAvet/DLMEzWAb8EJj5rH3xc/jGMj3FWkKDx1WCJU3Y=@googlegroups.com
X-Received: by 2002:a17:903:1aac:b0:223:7006:4db2 with SMTP id d9443c01a7336-23ac45e36c0mr55483685ad.31.1751044215877;
        Fri, 27 Jun 2025 10:10:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751044215; cv=none;
        d=google.com; s=arc-20240605;
        b=WKz17YIULJkesN5DJToA/Nkh7pAeR6dRFI71fktwfszivH7YgMn78g9yZM2XP5xhvC
         q29fWlM5rGSQDsCUOaHp/+csIGcBGXzUH2Uz5ikAruWiTJ/6b5hhH7/QAO+sZyPpoul6
         55wpqOQGJvHwAM3p5mPPw8fVLVngCDPA0Y0zQMgiywDKk1k6LgOKqoPX9/tyMWN8nLR0
         BQLBWFlMYMUc5HSYBNhI5bfzdhObt35nqRFMJRSrCDCo0tyFbUC+qc8sntUBt0ehwoYc
         TcMI3c4tbka+PmUT8GK8gvYsXYs7CedOu43MdZtVmkExgoygGGhbHqZs+WyQtnI60Q+v
         IiOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=NmwfJQJV+c9wJ1hezhGH5ZiqOmaiPpTqYKUu0exw8Qg=;
        fh=Lj9LfDSxtO9+R/IciARD/HgRK6V6cjgvzbPqJOdn7UQ=;
        b=M//Qas7Iq46RxZQbJ0JwBNELtCwZrLUpz8OfxdlBhv8NpMxbWV0odDoeGujdQk12Zz
         cY7hJCiMjGTGDfeNMBA+c1kzv1WptPSTQSGVKLWNrR1tGYBJzM8zSzDVzLZc4CVgtyo9
         HQtDwheIsI2sRaFQrfsaGH56uTOZWwCi73NhODyYvmaYO788/5ctn1aiZWXs9uTv73Ml
         dfaHEu1KWgJcYWncpX+60Y3NdZ8xDCk4BjX5tHYOnQTn/E1eKLdk9tLgujiyswMTzwFc
         OmDHLl5uZfus2q9vVGzMidCJzf7ugAnIdbJBNelFfFO5enXGle6OmNlO4eCylQVfsUjb
         P14A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZSVh4MWm;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23acb3501d5si918195ad.9.2025.06.27.10.10.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 Jun 2025 10:10:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-210-kr8ZbCo7O2S0RzUQCNa36A-1; Fri, 27 Jun 2025 13:10:11 -0400
X-MC-Unique: kr8ZbCo7O2S0RzUQCNa36A-1
X-Mimecast-MFC-AGG-ID: kr8ZbCo7O2S0RzUQCNa36A_1751044210
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-450d6768d4dso543125e9.2
        for <kasan-dev@googlegroups.com>; Fri, 27 Jun 2025 10:10:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVsNzbcO6S5gZfoLbmKe9caB96n/w2pCxb3NrFDe58wtddIB9zOwJ9r5m41JUgtrG6rJEm4Bmgf73Y=@googlegroups.com
X-Gm-Gg: ASbGncssbrNgE/GiBxD0eikacdo80GINvTlvi77Efln9b7yZ6Q2L1WJbgU2OucrW45/
	lplaWEWxa0PuMSPcRoXVKQkhbl2lA+jPVjzCTwt3ejDjtmK/MYhix8w3zHrqNQVtanGNJMog7rS
	AY/1CXl1vs5XjGrhsEdMqvUeSGuS6ni7DegKAoh/qyVOIgJiO4wfHpI7VYICGFaNVb0jVkLxaKV
	zvnT15pLrWRpZJhWYX7Xgn3ctxGDMWIGBQp9XW+WKGH4m9Ze1xaeokPwYcyTj5KoGCVtYq/fquT
	S+LrzgsRgFejTCi/VVLth1g26Mlfx2x314EBJdC5Rsu7xv64IcUORtyynmT3P5R+EefuQYtAyEP
	MjRGJnoOXCG31sDqD+VytkUE3Ppy+B/XJPP2VdSQeCVTjQopN6Q==
X-Received: by 2002:a05:600c:4f4f:b0:442:d9fb:d9f1 with SMTP id 5b1f17b1804b1-453918aefb4mr33154065e9.4.1751044210253;
        Fri, 27 Jun 2025 10:10:10 -0700 (PDT)
X-Received: by 2002:a05:600c:4f4f:b0:442:d9fb:d9f1 with SMTP id 5b1f17b1804b1-453918aefb4mr33153355e9.4.1751044209704;
        Fri, 27 Jun 2025 10:10:09 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f2d:5d00:f1a3:2f30:6575:9425? (p200300d82f2d5d00f1a32f3065759425.dip0.t-ipconnect.de. [2003:d8:2f2d:5d00:f1a3:2f30:6575:9425])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-453823c3c7csm85945735e9.36.2025.06.27.10.10.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jun 2025 10:10:09 -0700 (PDT)
Message-ID: <04116d0f-2815-4583-853e-e4295fb3d014@redhat.com>
Date: Fri, 27 Jun 2025 19:10:06 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 08/16] MAINTAINERS: Include GDB scripts under MEMORY
 MANAGEMENT entry
To: Florian Fainelli <florian.fainelli@broadcom.com>,
 linux-kernel@vger.kernel.org
Cc: Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham
 <kbingham@kernel.org>, Michael Turquette <mturquette@baylibre.com>,
 Stephen Boyd <sboyd@kernel.org>, Dennis Zhou <dennis@kernel.org>,
 Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@gentwo.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "Rafael J. Wysocki" <rafael@kernel.org>, Danilo Krummrich <dakr@kernel.org>,
 Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>,
 John Ogness <john.ogness@linutronix.de>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Ulf Hansson <ulf.hansson@linaro.org>, Thomas Gleixner <tglx@linutronix.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Luis Chamberlain <mcgrof@kernel.org>, Petr Pavlu <petr.pavlu@suse.com>,
 Sami Tolvanen <samitolvanen@google.com>, Daniel Gomez
 <da.gomez@samsung.com>, Kent Overstreet <kent.overstreet@linux.dev>,
 Anna-Maria Behnsen <anna-maria@linutronix.de>,
 Frederic Weisbecker <frederic@kernel.org>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 Uladzislau Rezki <urezki@gmail.com>, Matthew Wilcox <willy@infradead.org>,
 Kuan-Ying Lee <kuan-ying.lee@canonical.com>,
 Ilya Leoshkevich <iii@linux.ibm.com>, Etienne Buira <etienne.buira@free.fr>,
 Antonio Quartulli <antonio@mandelbit.com>, Illia Ostapyshyn
 <illia@yshyn.com>, "open list:COMMON CLK FRAMEWORK"
 <linux-clk@vger.kernel.org>,
 "open list:PER-CPU MEMORY ALLOCATOR" <linux-mm@kvack.org>,
 "open list:GENERIC PM DOMAINS" <linux-pm@vger.kernel.org>,
 "open list:KASAN" <kasan-dev@googlegroups.com>,
 "open list:MAPLE TREE" <maple-tree@lists.infradead.org>,
 "open list:MODULE SUPPORT" <linux-modules@vger.kernel.org>,
 "open list:PROC FILESYSTEM" <linux-fsdevel@vger.kernel.org>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
 <20250625231053.1134589-9-florian.fainelli@broadcom.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20250625231053.1134589-9-florian.fainelli@broadcom.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: Als039P67wFkoL0txDFn91gX5iLA8rz14FPO3pZlil8_1751044210
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZSVh4MWm;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 26.06.25 01:10, Florian Fainelli wrote:
> Include the GDB scripts file under scripts/gdb/linux/ that deal with
> memory mamagenement code under the MEMORY MANAGEMENT subsystem since
> they parses internal data structures that depend upon that subsystem.
> 
> Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
> ---
>   MAINTAINERS | 4 ++++
>   1 file changed, 4 insertions(+)
> 
> diff --git a/MAINTAINERS b/MAINTAINERS
> index cad5d613cab0..52b37196d024 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -15812,6 +15812,10 @@ F:	include/linux/mmu_notifier.h
>   F:	include/linux/pagewalk.h
>   F:	include/trace/events/ksm.h
>   F:	mm/
> +F:	scripts/gdb/linux/mm.py
> +F:	scripts/gdb/linux/page_owner.py
> +F:	scripts/gdb/linux/pgtable.py
> +F:	scripts/gdb/linux/slab.py

Probably they should go to the corresponding sub-sections. At least slab.py?

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/04116d0f-2815-4583-853e-e4295fb3d014%40redhat.com.
