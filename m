Return-Path: <kasan-dev+bncBDJ7DEXEZ4LRBJ6JRLCAMGQELJZ4ZIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 16F1EB1130C
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 23:24:58 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-315af08594fsf1352086a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 14:24:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753392296; cv=pass;
        d=google.com; s=arc-20240605;
        b=G3jSrAd960gcrNEwsmq5Ye9pwKxuGO7Kn+kcvkLLna1cxG6/dmIHSFO0jS1W81zdfo
         9UUihvMbuXTSAxOyNVx0uDG9YGZ0IEPQBHPbTuxxRRJybjW8hUVPKAdLcHS3nN0rNI+z
         b+GlIw4EJW6jl+ytN1/ZqOeMPhoNfJ2eHqR7m5ZRksudy0iKdFGERQVjhM4AHe4XLHLX
         fxczR0fjoTWPqP+Jr/0WPQY97d+A+G3vr/Uror0qEVpBcC+x7teTVhdZ/AjzN5QmWyS9
         2H0z6tEbFchUvpHTh9wMJF1CPZ8TxmxfQqeaMajkKTpSMpla8FHQPe6UPQhG+aFnW52L
         3YWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:message-id:date
         :to:cc:from:subject:references:in-reply-to:mime-version
         :dkim-signature;
        bh=eb0bLB9ogSw7xV1JZDhzX1hUuwi+3KqYJHdthWsyk3s=;
        fh=kg3EgnLLAQPLmdptPo/YXdxX0uz9lC6WI6cRBN5Tix8=;
        b=GUlZajHU34XU9jHeJfns3n+W8jIXM+oI7hEOks4uipBqDpf8ryXhzOvyr0bMESqwBV
         Y4ttLl3sO4KdYHtB6e7NYyB/94mCJVAce4urqKQmHX0uHjWDR+DmBPfvDXkpSMDfujMh
         i92ZPEfTWPYovPTVqxN65iXtaY/g2QF/QWO4WSlOxC3qhtcf/ifNaS7q2bV0JyBrI6EB
         QA7QL69vw+vxg2ZJ583UpraJXA+e6a8moumR7I+x2G1/nZanp/RqgQFR3+oxjbz0cd0B
         2/Mn+b4ftk3qyRahxEG+ilINNdGBpW7Wr8mPvw6k5GUj7WAsSL2cIODm7eHdX+AzhM/Z
         +ZzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=fail header.i=@kernel.org header.s=k20201202 header.b=TpVDTtmn;
       spf=pass (google.com: domain of sboyd@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=sboyd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753392296; x=1753997096; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:date:to:cc:from:subject:references:in-reply-to
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=eb0bLB9ogSw7xV1JZDhzX1hUuwi+3KqYJHdthWsyk3s=;
        b=Oy7lR7jr/neztvRr+5eSMCJHBiVkoX2uBOkCvmVcMQGQvd0EQgqjRW9TfDaqm84GHN
         E23rEer8XBCqupzRPXUAEieBonBuHuwI7wDt+/PATcxCUonqAPO43KS0ZsWCEXJ6GyzB
         T0cBmX07lqRGQ6lpifYyWQB9AmditoC+ehlTlG6P8NgMylhYy85msxpM32F/ZZRTJg4i
         BHxD4+RmDfEyBihff8Mz746IDL/pZVWtlROi/OYX/K7C1eb/WG7xSQOUg7N/okOyoruF
         Jn4LC2NpZep/I1qPShz0qlP71qGHpjFdimqkGhUyA4sYMUJsgtpoakMTA407VA3GPf8H
         9Qtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753392296; x=1753997096;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :message-id:date:to:cc:from:subject:references:in-reply-to
         :mime-version:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eb0bLB9ogSw7xV1JZDhzX1hUuwi+3KqYJHdthWsyk3s=;
        b=ddMOpeYLbYSpoZR4UpPSJsFAZhHvE7V3CCE6Vg6hoS6YhAJ2Bv8VWP7JyWAdbqTu1Y
         EGWH0f3qZ2z3enEPyPlyFzf5n2NAtEZbI7paBkDGPYcEMRmOb41adZ5Pzx2OMHk73DjI
         JtaDDtnTwuRkgreAwxrI3UiJmnQb6pGOAJxIKOuf9arC3Pj5Q5Gny2Zv1/os+u8xC2Ov
         ZQ7BoDnIeFP49myXQDTh1N4ZLji9PuUSiBeARJKlh8CAn4UZhNCfZ3MdihfIPBJ9a0Xp
         6CGyV9Z+4dkGidQani8lIzN7qrOvY3hslOvFwvD8l04hjT+f25j8UvV/E2yRUiT2kyLg
         dP3g==
X-Forwarded-Encrypted: i=2; AJvYcCXAKkO8adlSGpeO2IF07sm1D+IV7w6/HsWLJA+i8273CdJ8I3uSdhrgc+oPcQwy5m/1gWj95Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw9XE1XQxg9ctHf+tawyWAVnUyrwW5yndrBPydg7aBy4T/hYnfP
	sl0tClyx0FsdGeu+E29d/xDDIWM8a333y9Qgo/qzuLTd2rVNPgNv4DHr
X-Google-Smtp-Source: AGHT+IEnn/sjS7hgVl8eMx933K+iQa8LnagvcGbYRcu91TqENtfPKJBcg5JCS5daqcN7VdtLh7TKSQ==
X-Received: by 2002:a17:90b:2f8b:b0:31c:3c45:87c with SMTP id 98e67ed59e1d1-31e507b41eemr12582702a91.13.1753392296130;
        Thu, 24 Jul 2025 14:24:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdS5Wefg/A5Ucsn3gUjp57zfPV85vMmSHXqEM0DRVeFUg==
Received: by 2002:a17:90b:562d:b0:31c:c0bd:10f8 with SMTP id
 98e67ed59e1d1-31e5f9b738dls1207870a91.0.-pod-prod-09-us; Thu, 24 Jul 2025
 14:24:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIbJe2Fyy+yS1gU0RfCFpbNScEv5Epf1iM4AgAgkuXUJUW4I1qubcSFJxyXD3qbbKi3BbqGDN9CF4=@googlegroups.com
X-Received: by 2002:a17:90b:4ec4:b0:311:ea13:2e61 with SMTP id 98e67ed59e1d1-31e5085959fmr9139610a91.34.1753392294522;
        Thu, 24 Jul 2025 14:24:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753392294; cv=none;
        d=google.com; s=arc-20240605;
        b=BPDaKVdTHe+FnO3FsohzRkKS9EHBIWUhi69jDqjsujmUpTu7j2dFSMCyS5fdyVrlza
         51sKpbiH4/jqmbAVfz0NYf4/OSATz/0T1V8Zy/9KyWf8liT3ZGX4kOis03z959gQ6d+9
         B71AwmHFk0FBVR9riS5VOMi6qTfcybZbPuXUE+TShswdV9hb422WlwbFBsByQGcupb+k
         et03luUWSYDvEB3YOzfAhsa4/BrYOlcuFrvmpL4Fqhv59j2goHHBbVCF+W8NrWrycYbH
         HquHbqBnEDbB0CI08Hbl3oqonldmDD9QPZC6DwidXFlQ06FTJqtZt1So3lE9XUaDJuLi
         d/pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:message-id:date:to:cc:from:subject:references
         :in-reply-to:content-transfer-encoding:mime-version:dkim-signature;
        bh=XF9wki9AjDCraP3PkW3hEqMnoy89UeAnuDiZvWolUoQ=;
        fh=gGaMhwQEk4pMf1rKeiaovC8PmkmDdduoC/y7teRHQhM=;
        b=CZlrWP5sBS9UmR1ocibpl72irkxBtq6+XIpIbwHC7py0f4sRkHyA3FnlniuYZWlQ3i
         swvZgvwZqbwqgM3rXKUrjVZaQgI9kXsIoCRyVgn9XaZ7onBSuAprO5DaCEGpKEDaxflB
         padPye9srH0X3/uMjz35bDXiYaymDFcVb9xzqNuuCqmDRxLxiwyux1zaDXYdmyX45ROk
         7lDLeu5FpToHS8A+ALuvOd+e0V4o4G5gHII+pmHPoryEURZuGXNdhQXBvSrd9vX1N4Da
         3qt+XhCjN4JIA+NvbiU060htcg04VkjVluzIgVvrvxNY9Pmwv2aoYu+CCyK0dUBNmtMX
         Yz/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=fail header.i=@kernel.org header.s=k20201202 header.b=TpVDTtmn;
       spf=pass (google.com: domain of sboyd@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=sboyd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31e6224edafsi109271a91.1.2025.07.24.14.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Jul 2025 14:24:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of sboyd@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 14F5243CEA;
	Thu, 24 Jul 2025 21:24:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D667CC4CEED;
	Thu, 24 Jul 2025 21:24:53 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
In-Reply-To: <20250625231053.1134589-2-florian.fainelli@broadcom.com>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com> <20250625231053.1134589-2-florian.fainelli@broadcom.com>
Subject: Re: [PATCH 01/16] MAINTAINERS: Include clk.py under COMMON CLK FRAMEWORK entry
From: "'Stephen Boyd' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Florian Fainelli <florian.fainelli@broadcom.com>, Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham <kbingham@kernel.org>, Michael Turquette <mturquette@baylibre.com>, Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@gentwo.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Rafael J. Wysocki <rafael@kernel.org>, Danilo Krummrich <dakr@kernel.org>, Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, John Ogness <john.ogness@linutronix.de>, Sergey Senozhatsky <senozhatsky@chromium.org>, Ulf Hansson <ulf.hansson@linaro.org>, Thomas Gleixner <tglx@linutronix.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Liam R. Howlett <Liam.Howlett@oracle.com>, Andrew Morton <akpm@linux-foundation.org>, Luis Chamberlain <mcgrof@kernel.org>, Petr Pavlu <petr.pavlu@suse.com>, Sami T
 olvanen <samitolvanen@google.com>, Daniel Gomez <da.gomez@samsung.com>, Kent Overstreet <kent.overstreet@linux.dev>, Anna-Maria Behnsen <anna-maria@linutronix.de>, Frederic Weisbecker <frederic@kernel.org>, Alexander Viro <viro@zeniv.linux.org.uk>, Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, Uladzislau Rezki <urezki@gmail.com>, Matthew Wilcox <willy@infradead.org>, Kuan-Ying Lee <kuan-ying.lee@canonical.com>, Ilya Leoshkevich <iii@linux.ibm.com>, Etienne Buira <etienne.buira@free.fr>, Antonio Quartulli <antonio@mandelbit.com>, Illia Ostapyshyn <illia@yshyn.com>, linux-clk@vger.kernel.org, linux-mm@kvack.org, linux-pm@vger.kernel.org, kasan-dev@googlegroups.com, maple-tree@lists.infradead.org, linux-modules@vger.kernel.org, linux-fsdevel@vger.kernel.org
To: Florian Fainelli <florian.fainelli@broadcom.com>, linux-kernel@vger.kernel.org
Date: Thu, 24 Jul 2025 14:24:53 -0700
Message-ID: <175339229300.3513.16413844188162316683@lazor>
User-Agent: alot/0.11
X-Original-Sender: sboyd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=fail
 header.i=@kernel.org header.s=k20201202 header.b=TpVDTtmn;       spf=pass
 (google.com: domain of sboyd@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=sboyd@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Stephen Boyd <sboyd@kernel.org>
Reply-To: Stephen Boyd <sboyd@kernel.org>
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

Quoting Florian Fainelli (2025-06-25 16:10:38)
> Include the GDB scripts file under scripts/gdb/linux/clk.py under the
> COMMON CLK subsystem since it parses internal data structures that
> depend upon that subsystem.
> 
> Signed-off-by: Florian Fainelli <florian.fainelli@broadcom.com>
> ---

Applied to clk-next

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175339229300.3513.16413844188162316683%40lazor.
