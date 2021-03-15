Return-Path: <kasan-dev+bncBC33FCGW2EDRBANKX6BAMGQEGQLNRAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id C7C8E33C8A2
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 22:43:29 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id f3sf15648477wrt.14
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:43:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615844609; cv=pass;
        d=google.com; s=arc-20160816;
        b=t8FIhqSor+x0NT0te6/hn8ZE0E/nIxRflIn8hJo33gFKTxPeDs+/6UwPdkh1/9a0j1
         3OPWQh+bOl4zZRDLiBewVV2iY3iM83/M6hB67z5MbAeUWCcmGJ1MeP28kCJQqBo4FpTL
         V9a0D5Xfx3JkdbMucfGjRwz66Yx20rO81iDBCoo8Ss4DraV5jGVXDPppt5t8nSM1VpHS
         +kPB71smgRHTwGOHMIV7yOeFfH1j26EtlamzggZSNl9SH7a0JXJgzFJZSuWUf1+buHCf
         IoSGOYpUPPkgqt42xw5CrcB6qQZA20aDqq6Q3kTiKIFcvG7Cl5mDY5dnQx4vFLHxFioh
         zO6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=2fBDePKswCTd1yXXQI33ddszAvr9v5gYxmTctnZsolU=;
        b=ejwH2SZz+nLiFDFLpm7wzCx/rQ2rlr7GrECUNnCw4IGTHvHe4hD1Re6BFx09FceDIo
         VuZbP/kS7zNKmbe/DipljgM++eMvVFPtMqnpVQM9jIp0ua7TKt/RsJwfYVdTENSqVagb
         JZg1LlA5eI9nBznVKqeUx/xDVVF7nvtLbd10+SWUk6QHFFWLNom73REBZNsmeqWa/9HM
         O3t1rXXkUGtK32vWQhcmatNfhZUQoN71p4vn6XsKXz1L9Z97EzYuVskbjaXO9z40objO
         hXRaG2fRLQPFyXRGsP4g1yP81I7ShAtJDXGiUS10DHKsj8I1ZBbvz9eDNu9cGzICR5Rj
         vpcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=Y3Xl6hws;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.162 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2fBDePKswCTd1yXXQI33ddszAvr9v5gYxmTctnZsolU=;
        b=rcFocPxoebbJzfhD8HnHmc5R7A7erKsKx4730hCeUhnzoQCwZ6+E9e25SBsHb+aCU4
         Eyorj7yrG4+S4QH2SZWEsrpssexA5FSBqFIr20EkDXmJzPR75rxZZFVbk/5XYgjU1Rpd
         QRu2Mi19qkr8i17NpwK7lojr1lyvWHjoFGvOVRaAU13GkJ/F+Q2qxd86TIJQkp0PdW34
         YSQh45oJrLwrLfuFQwT/CLslexqJLTC4/wA38HzzQM7qzxfuQlhqSFjmr8JvrPpjsFE0
         uF8gLaIZ46HfnnZKAPtloD0a9xZpyIek9hmk6iLKiXDR7b9YJdqprqKKfoBSYAIG4rWL
         6wWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2fBDePKswCTd1yXXQI33ddszAvr9v5gYxmTctnZsolU=;
        b=getxmEaFDTjMzkeCsFHhpvVrLaK+nbrD4vymUa1wjCUKZZwMXbsimO6aykiJXrDiq3
         fa+HcSDGPh6cAbFL6MZxuiZnDD6k7MqHEiqb9HGpGdMs8E5gZrMK0/82JpQ5WHICafbz
         b6yWjTE19ZJ8KiBg220DKa0tNRTM7DuenB21AN3lvPtLLE9h+IPeRT9gJBHj8yhDjZvt
         h03cOPbnuXW13rxy8FgH+I+nPwwIXd0qldsbrFiW6KJHVyz7/dJpBxobgRmMNStifR0B
         /Y/EA/Ap5R+XrzkKSOn+T6leTUYAcv/KJEsI3nUUTQ+CSPas1HwpGDv4PENoZQyRhEWa
         HAdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Ei7DVWTdv7JgLKfCprHj3AEdwBj4kpcV96/V7WCSJ5V1tuNJW
	XAM3PA2iReLZiOx3AqxkHSY=
X-Google-Smtp-Source: ABdhPJyKDIFzfhehCBVukiJJ9t6uhHgTNRNj6vc3GIJNmhmvdhqmAQc4S5UPb2Fu1H9uOmHz6Gplgg==
X-Received: by 2002:a5d:5744:: with SMTP id q4mr1621582wrw.390.1615844609616;
        Mon, 15 Mar 2021 14:43:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e6:: with SMTP id g6ls1261260wrd.3.gmail; Mon, 15 Mar
 2021 14:43:28 -0700 (PDT)
X-Received: by 2002:a5d:4587:: with SMTP id p7mr1552475wrq.205.1615844608747;
        Mon, 15 Mar 2021 14:43:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615844608; cv=none;
        d=google.com; s=arc-20160816;
        b=DFCYIrCQOSux/tT1KjdLx9psE2/Gzx23s6ZQ6nJpA+C9HEneDbtCfUsoHEZyNggEsO
         h4LyCWBHxhTvL/XsFTTwwGfdUgen/PDoSLQJjxKzS360VYXrJutSHouiyLlecMQSCSZr
         FMoyxFel1xLE+M21NfY/vGyT9RbCWxOHZ++IPLusl3Hk1+tCoek408dEyMIbkKhQN2LR
         kkobsf69J+Ra84B48emAj6Ea1WwxO7IaBnVl5I4k1CyB/0hOgzCnueJbNfu9TEpQpOr3
         x09DyKUkrB0mnX0w+1eBYVWxdzz8nr6+VZ8L9mgJcqQLypdrAv1SQ4Vh2ZBlL9WyHm9k
         2zBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=M9F4yfo0Mkt0f1pC0t4RFbu4UICqYrDPTZLlD+owu2U=;
        b=KCNvu0q/7Cp5X/YOqXSRYGdlKNd56YIcl02lfkQinId+M1y8IZ6hciERfJjNYo0exZ
         WaCUcpQdd4JU6N1WE33UctfR2aEUSea9GudvtzVK4blj/icCgtUE92Im9au3YEaalCh+
         5TKvc/VjbvcKW1nFRcvU3PxAx3CMMQk9tZBSXrS688+ufOuau9WsPobVeGRBe50JIxhY
         YXQu9jWf9cd++Z8RrbBAEirboRFwahTNeEGWOmUmXVpH4UA5ZDj+JUDE08wHWhuIHZjY
         7fRE3GUPLqyX8VufaF5jZSGZo60+6Q/kuZ5haNb3FvJuv/XgR5MS5cuH6FUUQqBvfHPS
         ryMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=Y3Xl6hws;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.162 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Received: from relay.yourmailgateway.de (relay.yourmailgateway.de. [188.68.63.162])
        by gmr-mx.google.com with ESMTPS id y12si367210wrw.3.2021.03.15.14.43.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Mar 2021 14:43:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of info@alexander-lochmann.de designates 188.68.63.162 as permitted sender) client-ip=188.68.63.162;
Received: from mors-relay-8201.netcup.net (localhost [127.0.0.1])
	by mors-relay-8201.netcup.net (Postfix) with ESMTPS id 4Dzqfm2M7tz4Xvn;
	Mon, 15 Mar 2021 22:43:28 +0100 (CET)
Received: from policy01-mors.netcup.net (unknown [46.38.225.35])
	by mors-relay-8201.netcup.net (Postfix) with ESMTPS id 4Dzqfm1xtzz4Xv9;
	Mon, 15 Mar 2021 22:43:28 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at policy01-mors.netcup.net
X-Spam-Flag: NO
X-Spam-Score: -2.901
X-Spam-Level: 
X-Spam-Status: No, score=-2.901 required=6.31 tests=[ALL_TRUSTED=-1,
	BAYES_00=-1.9, SPF_PASS=-0.001] autolearn=ham autolearn_force=no
Received: from mx2e12.netcup.net (unknown [10.243.12.53])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by policy01-mors.netcup.net (Postfix) with ESMTPS id 4Dzqfk6jqDz8sX5;
	Mon, 15 Mar 2021 22:43:26 +0100 (CET)
Received: from [IPv6:2003:ed:7f03:fff0:8c65:f932:36e8:7b85] (p200300ed7f03fff08c65f93236e87b85.dip0.t-ipconnect.de [IPv6:2003:ed:7f03:fff0:8c65:f932:36e8:7b85])
	by mx2e12.netcup.net (Postfix) with ESMTPSA id AB678A128E;
	Mon, 15 Mar 2021 22:43:25 +0100 (CET)
Received-SPF: pass (mx2e12: connection is authenticated)
Subject: Re: [PATCH] KCOV: Introduced tracing unique covered PCs
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet
 <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>,
 Wei Yongjun <weiyongjun1@huawei.com>,
 Maciej Grochowski <maciej.grochowski@pm.me>,
 kasan-dev <kasan-dev@googlegroups.com>,
 "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
 LKML <linux-kernel@vger.kernel.org>, syzkaller <syzkaller@googlegroups.com>
References: <20210211080716.80982-1-info@alexander-lochmann.de>
 <CACT4Y+YwRE=YNQYmQ=7RWde33830YOYr5pEAoYbrofY2JG43MA@mail.gmail.com>
 <01a9177f-bfd5-251a-758f-d3c68bafd0cf@alexander-lochmann.de>
 <CACT4Y+ZPX43ihuL0TCiCY-ZNa4RmfwuieLb1XUDJEa4tELsUsQ@mail.gmail.com>
From: Alexander Lochmann <info@alexander-lochmann.de>
Message-ID: <8841773d-c7d2-73aa-6fa6-fe496952f2ba@alexander-lochmann.de>
Date: Mon, 15 Mar 2021 22:43:25 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+ZPX43ihuL0TCiCY-ZNa4RmfwuieLb1XUDJEa4tELsUsQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: de-DE
X-PPP-Message-ID: <161584460608.10283.10375834804910803558@mx2e12.netcup.net>
X-PPP-Vhost: alexander-lochmann.de
X-NC-CID: y7MpuFzfc+D6xQwpyqU+yQrRwg5OG3Qa4gGl9FcY9NcwZPR4oX0OeM0v
X-Original-Sender: info@alexander-lochmann.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alexander-lochmann.de header.s=key2 header.b=Y3Xl6hws;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates
 188.68.63.162 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
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



On 15.03.21 09:02, Dmitry Vyukov wrote:
>>>>  static notrace unsigned long canonicalize_ip(unsigned long ip)
>>>> @@ -191,18 +192,26 @@ void notrace __sanitizer_cov_trace_pc(void)
>>>>         struct task_struct *t;
>>>>         unsigned long *area;
>>>>         unsigned long ip = canonicalize_ip(_RET_IP_);
>>>> -       unsigned long pos;
>>>> +       unsigned long pos, idx;
>>>>
>>>>         t = current;
>>>> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
>>>> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t))
>>>>                 return;
>>>>
>>>>         area = t->kcov_area;
>>>> -       /* The first 64-bit word is the number of subsequent PCs. */
>>>> -       pos = READ_ONCE(area[0]) + 1;
>>>> -       if (likely(pos < t->kcov_size)) {
>>>> -               area[pos] = ip;
>>>> -               WRITE_ONCE(area[0], pos);
>>>> +       if (likely(t->kcov_mode == KCOV_MODE_TRACE_PC)) {
>>>
>>> Does this introduce an additional real of t->kcov_mode?
>>> If yes, please reuse the value read in check_kcov_mode.
>> Okay. How do I get that value from check_kcov_mode() to the caller?
>> Shall I add an additional parameter to check_kcov_mode()?
> 
> Yes, I would try to add an additional pointer parameter for mode. I
> think after inlining the compiler should be able to regestrize it.
> 
Should kcov->mode be written directly to that ptr?
Otherwise, it must be written to the already present variable mode, and
than copied to the ptr (if not NULL).

- Alex

-- 
Alexander Lochmann                PGP key: 0xBC3EF6FD
Heiliger Weg 72                   phone:  +49.231.28053964
D-44141 Dortmund                  mobile: +49.151.15738323

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8841773d-c7d2-73aa-6fa6-fe496952f2ba%40alexander-lochmann.de.
