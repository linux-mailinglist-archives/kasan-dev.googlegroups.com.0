Return-Path: <kasan-dev+bncBAABBY6DQKRAMGQEKVFYGFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 71B2B6E87ED
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Apr 2023 04:22:29 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-32b532ee15bsf13984295ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 19:22:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681957348; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pzbvjlo/5fZWNNybw88FZxg99K0WowofZVSk/2+OyZEfXtphLquW/cd+S+5Nn7Tf7W
         dD3MP+4qJI/6ebekH7PPrfs1RYvAylk1uNGeakERAp3kxYBnhJM33Q5xXozBzmpZOH3/
         F/Q3Jx9+BNbTP00vxK4VNDzqrYpU+8w9ido6xMrPqOHdrWr8M/DZ8yWoDBC5MuRxxq6H
         W4surFkwEaYqhOPzYDV+kumEhHCjNmgs6QrMhgZn0b7bigpzNF5mBN9GTJppfvJLkVwJ
         2Ik1mRKwbfKXZ2IJLZQmSqDZpGTxQiQxgppi5Zd6qgNfdd96KVbDmFvIrlNSqElGz/z0
         hxOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=Sp3prEglwW5en0t5VEF/LA0LE+Np/yCH4xsnR0YnoFg=;
        b=j0Bj5x9NbRUMRZzjqJ+fNAIs2iE+qEsAIqwIkA8K+jOXHDNYIP3AhHqkc88PjhrBlw
         GFAYwFU4xdWpRhhGMNvz+zIejV1cKrU9m7/fxeMIYie4a0QQR6HdK8NyTqRF/XzqH/K3
         gvtYPXQoQ2IIrrHSthbDO/PTNGonQEhC0FtlA5Xv6lfAmoPcMUs/dknxgOaMGzQIp4G4
         YXY3tXp/OOJ2f9MVWjQMhFrcQ7Q512BAhBjg2odaPjLhj7hAkDaax2oDLlK70JVAea/T
         px61QtHIh3M0kIUWLJ3sjIvnPlfFPFVJMk5KsLmv62R+TaRlq0LaYqmGTozne5vwJbib
         5zUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681957348; x=1684549348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Sp3prEglwW5en0t5VEF/LA0LE+Np/yCH4xsnR0YnoFg=;
        b=eNqV4RHSrx19nzOriezXzB+JHPK9tKG0ykYJfzvnGpB48R+7sOmKBEZma0XtW6HcTI
         2gwZbihFJ39A8HzfFN/+6+xzq63SIWKogxfnhdQwteMMPgraY/Py3q35x4g2LqYqE5Ad
         dTkdW/Y5XBlSccUntr4gx2fct4KgADb5hYIP+c2+ci7yCDxBeZ2LHEr5n3nQqkyLTC69
         MoSqvgp6ze9J75jQ0KcBBG36AfhKlFMirKxg5NwZ0l/hWCaSQLnfDV0XeGV1++kSRakA
         yu0NkXQoJH++70S6iC6dZiVtp6u6gtvsAETQcBCQ5Fec5ppPBFd8fSXRRyWmHgQXXsCA
         hcNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681957348; x=1684549348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :mime-version:user-agent:date:message-id:from:cc:references:to
         :subject:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Sp3prEglwW5en0t5VEF/LA0LE+Np/yCH4xsnR0YnoFg=;
        b=hPbm1mYc9SeJjzTwarE40FEaJocxvuoO4lTIzPtgcbZnKSUdVbYdBLzTTKalEdaTqZ
         IpHPJKIVkcu2UOdNg2/3jUiVN3ChZZ3K6DXdOpz10LxgKXHocUy53vJDq42kq8rTsCgw
         xgmnLD7x+GuVC0sSkojNGY5O33xHRVJdlbNYT5/eSREqgo9eVJ/7Z/SvK6S41LL2xCrl
         l9KsOwsmPiPcwITZo7w78jgInncYq4p5DWblNR3P47KweCgYZ5l2vJjzcM7HBMWz8CKn
         FAXTo/aCE+5e+ufTiKUcb77C0t1GDLqod18JpqqYCb+rqX5E9ndbr74lr3ZYXisjo01c
         Cm+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9eR4A8mqD+AQQP9f3XA7/Lo5Lz3qiIsSMXWy3SysJ2GNpgYO0Hx
	99Cq1mswgUSi2rQ+eGcX6ms=
X-Google-Smtp-Source: AKy350baMnqgEMEeVORCFQ/D7D85EoRVL/Dt/EDohc+pyRK6JfPV4sJ1VOkNQPeDeRw82KHTI244Wg==
X-Received: by 2002:a05:6638:4806:b0:3c2:c1c9:8bca with SMTP id cp6-20020a056638480600b003c2c1c98bcamr1260098jab.2.1681957347287;
        Wed, 19 Apr 2023 19:22:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:4015:b0:763:6eb2:fc43 with SMTP id
 bk21-20020a056602401500b007636eb2fc43ls104979iob.11.-pod-prod-gmail; Wed, 19
 Apr 2023 19:22:26 -0700 (PDT)
X-Received: by 2002:a6b:7d44:0:b0:763:5a8c:2e14 with SMTP id d4-20020a6b7d44000000b007635a8c2e14mr298438ioq.6.1681957345941;
        Wed, 19 Apr 2023 19:22:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681957345; cv=none;
        d=google.com; s=arc-20160816;
        b=hbPPFbVOEQXO0k4g656TzZCfFgErOH+Cg9LSYrZ8CM0HjsCgNDkWLBsR1TYilX7dAC
         /xm654W+zEYrCTURkLW/31KtE/Pg7VAjJHqsAobxZmEpRXvrCaD8EFCbWjcETK44HV74
         c1Y8evVpmKxDbkcmo6kWZ8aBrCgSkikA5NYt+9jUPYKnK6oqPOkvRZz56+pgWf7+5SjV
         LfA471tvKoetmWiFaWxPi83lTOGovdlGtWKTejDjI/VeuUqJ/Tk0RcumG9mxEdWzTMiz
         PG/SrkwUUQsl2P8fLOSbSCrzbwC8lJvTVY6+Gr9MpExQwv4nHcSb3axpaNBAIe6pMKHv
         X3vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject;
        bh=m/J9nAevPnI2bU3GHFQSHa3GMRQTgbrQzzseb4V8mds=;
        b=B06wlDk8+sLpdfPvWy4tUXw6NIsPBHnTD5W4/x2FWW9K6Jmmvv9hac/d8hIKk8AQF7
         Pyqmif90fQBbzJ6qRX74z5dMjqdoAyMrJlav1zTZGfeLoxEPDiITVZAfqvWzbx74n8v2
         GGjiqAcjiwf9mHwzKr4VGWn/XvWH/w5y4sL0JECTr/IRoKLlUlI4kptE7GSYqyBCauAZ
         1B62kJFBzJI4gvYAyIiSSue0TENr1z7b05iFq1UCwxjFY/2ov8x5z+K+46wHv4T25DjO
         n1ANUKFUTZt1MxHNQbh52+PpWooAsCFMGcDwGE0o4q+YD6aQ/ALFQNt0lIk0GbVX/Fzx
         iI2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id bi13-20020a05663819cd00b00409125e3b19si32525jab.2.2023.04.19.19.22.24
        for <kasan-dev@googlegroups.com>;
        Wed, 19 Apr 2023 19:22:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8Dx_5e_oUBk7DwfAA--.49272S3;
	Thu, 20 Apr 2023 10:21:51 +0800 (CST)
Received: from [10.130.0.149] (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Axlry+oUBkj2QwAA--.14S3;
	Thu, 20 Apr 2023 10:21:51 +0800 (CST)
Subject: Re: [PATCH v2 0/6] LoongArch: Add kernel address sanitizer support
To: Qing Zhang <zhangqing@loongson.cn>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Jonathan Corbet <corbet@lwn.net>,
 Huacai Chen <chenhuacai@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20230404084148.744-1-zhangqing@loongson.cn>
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
From: Tiezhu Yang <yangtiezhu@loongson.cn>
Message-ID: <7991cc06-cf68-8e2a-b008-760cb7b17f01@loongson.cn>
Date: Thu, 20 Apr 2023 10:21:50 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:45.0) Gecko/20100101
 Thunderbird/45.4.0
MIME-Version: 1.0
In-Reply-To: <20230404084148.744-1-zhangqing@loongson.cn>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-CM-TRANSID: AQAAf8Axlry+oUBkj2QwAA--.14S3
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29K
	BjDU0xBIdaVrnRJUUUBmb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26c
	xKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1Y6r17M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vE
	j48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xIIjxv20xvEc7CjxV
	AFwI0_Cr0_Gr1UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIEc7Cj
	xVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zV
	CFFI0UMc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUtVWrXwAv7VC2
	z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JMxk0xIA0c2
	IEe2xFo4CEbIxvr21l42xK82IYc2Ij64vIr41l4c8EcI0En4kS14v26r1Y6r17MxC20s02
	6xCaFVCjc4AY6r1j6r4UMxCIbckI1I0E14v26r1Y6r17MI8I3I0E5I8CrVAFwI0_Jr0_Jr
	4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y0x0EwIxG
	rwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8Jw
	CI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2
	z280aVCY1x0267AKxVWUJVW8JbIYCTnIWIevJa73UjIFyTuYvjxUcCD7UUUUU
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

Hi all,

On 04/04/2023 04:41 PM, Qing Zhang wrote:
> Kernel Address Sanitizer (KASAN) is a dynamic memory safety error detector
> designed to find out-of-bounds and use-after-free bugs, Generic KASAN is
> supported on LoongArch now.

For now, the arch-independent code (patch #5 and #6) has been
received tags,

   Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

What's the merge plan for this?
Take it as a whole through the loongarch-next tree?

Thanks,
Tiezhu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7991cc06-cf68-8e2a-b008-760cb7b17f01%40loongson.cn.
