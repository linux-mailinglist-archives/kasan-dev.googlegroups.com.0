Return-Path: <kasan-dev+bncBCVJFSG3KIIKN7WFSMDBUBENOKFS6@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 40CE5518D07
	for <lists+kasan-dev@lfdr.de>; Tue,  3 May 2022 21:14:49 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id b65-20020a509f47000000b00427b34634d3sf4568281edf.20
        for <lists+kasan-dev@lfdr.de>; Tue, 03 May 2022 12:14:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651605288; cv=pass;
        d=google.com; s=arc-20160816;
        b=iCIM9hDgSZcNCUl2v2CTxWtpxCOlnwGo6Eb6pYdFs9N3csSx0M4VeOr5HA/848YhU1
         ZRjRK58eKsLnMRJHnzQBXQFExtuZK8KBqyrBm51IVYkgJ9mr3r57/RQD909wxKornGUi
         rTX9fKxr1NE3PbSG3R8hnMYsoNz/PmQ96pUho2Yo8gr4tnc+Bgb7HtpDJEsKRAW06szt
         /qTtT2X+Ui3qcFmTtbGML6fuN8YQIcQ7c9GEtStuapSbUHwNTACNu4WQnt1yGcCFRDsq
         AXCTU2T0dgIfifLLZ/SCPEPZW2rxjChxUK9ki8tXdJbug4uqJLWaxiAqqHVCfHxRiibT
         7IBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=9lBiE3tZa8A+dfXs/BtFtYcVFU8hFVAH06gzADYVhxk=;
        b=bDLakLbTxoXcQVX2RqeTO1ORDKqRlChzieYrFbKiunZsscf6L8HmY6KkY/uzjPh4lj
         6hXQZLxA9xccpnJn7UoY0Z6cR5P9AQ/OhiZQmtVyra1q8/s6vUK2pg5pRTq8/DpQWDG1
         Qy0A4OemaT+nZ24hDOhkotaLCNEs3LbUlboMgSuQAR5Ot6qah43seJ2ZqzSLmKUhm4QL
         gtayDmHjJoPq5zgM7mpeZoJnpHyr5YvmetQBwsKEhY46fovcFIDw+XX4UQc/PkaKWuQf
         rsTT9/VSKb30/2J8HeQFKHDuF/cf3tqtlqht/QL5oO03L30sND8Yr1fMhs5SREQuor5o
         Kkzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=nJKRf3Pj;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of john.ogness@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=john.ogness@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9lBiE3tZa8A+dfXs/BtFtYcVFU8hFVAH06gzADYVhxk=;
        b=URrCGMpCV2ZE4RjBk8+/1hA5IOix6XJdwQRq1DXN30vxJRLF57bzvccIZelWTyqFgZ
         i+r3MGN6RQhjc5xtcoLJH1BJka+E3+7fnlxKOeSiIXqSsWHEASs/qZq9PiwWtLXy5xyC
         1Nw7bJGW/F9bpV7TLR/JXWV2VJJWscETeVkRdsRhif2TDuYWm0geh7nqbugN0qn1DHmx
         fTdTCCVLckibrA1J3VQVrCAm/WUm6e2uc1DEd/DetUJ4yDlfIaG5wUJDA9x6Ht0NXyS7
         80+/PihausL52Iq6Bbo5lYM10EN/qzUw9GrJX8uiF9tmS+uqIj76mAAZ+RNJO4Blr4aJ
         sv9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9lBiE3tZa8A+dfXs/BtFtYcVFU8hFVAH06gzADYVhxk=;
        b=XK8v0SASUtn+bPG+gP9FzYGUUMqRWqtcEEai9JMu1ykeDGAUKEEJ7zMslC21c5ATJE
         BqrLxHCzIz5QVvhKrfdxdRsanh4ZszScZBjyMbSY92sT78jE5E2jPy+d8hxuHRFVSlIV
         kT63AbFTedfYf4qjEWGqsijsmad6hYDo+tOnU1wjHx0e68TLpUSvrF4Z0m6FJEgQgznQ
         M033yCoCE4Ju5Sa72GDPYZXwL4GgbU9biwqrG4xPMeD1jTb+lB0cZyVwIVVIrgVlFLe5
         2x4g/ZfZnAfw7udhQ8vQX9KmXri1cyDE86K/y3e8gSKK8aw5ZvuUw34NcaDxH4ekCAzf
         kR+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5339akt5ELyCllIXoq50owmP27ORBHzqAGN4kLeIK1aRSsrbSj0I
	1lZxa14ZiGD65LIbFOvSspE=
X-Google-Smtp-Source: ABdhPJw/l0uDGp2sYXimUUitfy/mdQzxy3Ujn174UNrMZ74nQommRirs70E4cQqOtYOjdIML38ZQiw==
X-Received: by 2002:a17:907:2da6:b0:6f4:440c:7cb9 with SMTP id gt38-20020a1709072da600b006f4440c7cb9mr11604661ejc.55.1651605287011;
        Tue, 03 May 2022 12:14:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7f1a:b0:6f4:7118:d7c7 with SMTP id
 qf26-20020a1709077f1a00b006f47118d7c7ls2637558ejc.1.gmail; Tue, 03 May 2022
 12:14:45 -0700 (PDT)
X-Received: by 2002:a17:907:94ca:b0:6da:b785:f067 with SMTP id dn10-20020a17090794ca00b006dab785f067mr17400609ejc.654.1651605285756;
        Tue, 03 May 2022 12:14:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651605285; cv=none;
        d=google.com; s=arc-20160816;
        b=OoH0XZYm5aNtIOklUK8e3l7bf6pv8RZzkPfbK7N5ddnKWd69pXQjAZPilKsJ+XI3T6
         MYuRZwi8FIvht9K86evpif0PoD1FZxLvE7nVcAvDqgK51PmJyVUeak3iqQtu46/ZGx3F
         wHQcyBCNRxbcEqiawxQHu8qXYe4EuYcp2eKBZQmVwBp2Kl2z662e4ZPMjaCzhmSiNcUB
         KnPKdMrGwExBXq9GPh8TXBpaKQj0g2ddfgqMTShqUo/2Ykbzh7A11fy+Kg0UfUjh2uyO
         d5IzkujE1hlOXHnF4VNZkB3i2y0m4l2P5gRzA6fp/dpFoCIDbi8Ezs0bAzllupijQ/IB
         8TNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=q6tI8vR0YuSpmVwH6PHCfJgGfXuGMuhIaoQrWI4CdGw=;
        b=pcW9WZPaJKWAcN9yVngpIUZ3R4rkDcFgxGMAIOIChM7bPvO/+xcWOJmiATRCaioNj1
         l1lmyLi8Z1Wg3g/JEc25sN2t84+fKQCpvpMc5zhqvNwbfYqCYoz7ESChiWNU+HDJgSYX
         5O9HGwdzUu8PZRDu8/QaZowuYWrC9qrVIUvZj0lu/TqglQeMn+vR/lGXxlsoLZ+XvPit
         CDPAELteWWBwwUQ1nlzMTOieBV59h3pLXz9F5DAFhxUHB1kdKe8eT8SFWI/CGggWlXb/
         9doxBdnRzT7dcSj1ATCGJBhc37/fwxaRjAv9ab62tDeZoIn9Q+//EZZcxzGZU3gj50ZW
         4Z1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=nJKRf3Pj;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of john.ogness@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=john.ogness@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id gv43-20020a1709072beb00b006e8421b806dsi1223485ejc.1.2022.05.03.12.14.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 May 2022 12:14:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of john.ogness@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: John Ogness <john.ogness@linutronix.de>
To: Marco Elver <elver@google.com>, elver@google.com, Petr Mladek
 <pmladek@suse.com>
Cc: Sergey Senozhatsky <senozhatsky@chromium.org>, Steven Rostedt
 <rostedt@goodmis.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>, Johannes
 Berg <johannes.berg@intel.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Naresh Kamboju
 <naresh.kamboju@linaro.org>, Linux Kernel Functional Testing
 <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
In-Reply-To: <20220503073844.4148944-1-elver@google.com>
References: <20220503073844.4148944-1-elver@google.com>
Date: Tue, 03 May 2022 21:20:44 +0206
Message-ID: <87r15ae8d7.fsf@jogness.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: john.ogness@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=nJKRf3Pj;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 john.ogness@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=john.ogness@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2022-05-03, Marco Elver <elver@google.com> wrote:
> One notable difference is that by moving tracing into printk_sprint(),
> the 'text' will no longer include the "header" (loglevel and timestamp),
> but only the raw message. Arguably this is less of a problem now that
> the console tracepoint happens on the printk() call and isn't delayed.

Another slight difference is that messages composed of LOG_CONT pieces
will trigger the tracepoint for each individual piece and _never_ as a
complete line.

It was never guaranteed that all LOG_CONT pieces make it into the final
printed line anyway, but with this change it will be guaranteed that
they are always handled separately.

I am OK with this change, but like Steven, I agree the the users of that
tracepoint need to chime in.

Acked-by: John Ogness <john.ogness@linutronix.de>

The ongoing printbuf/seq_buf work [0] will hopefully someday do away
with LOG_CONT altogether.

John

[0] https://lwn.net/Articles/892611

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87r15ae8d7.fsf%40jogness.linutronix.de.
