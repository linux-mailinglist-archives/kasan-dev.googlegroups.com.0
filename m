Return-Path: <kasan-dev+bncBCN7B3VUS4CRBNFKUWAAMGQE2U2L6JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id AC62C2FE75D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 11:19:33 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id p80sf1805200ybg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 02:19:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611224372; cv=pass;
        d=google.com; s=arc-20160816;
        b=P7Iccz0fB8g2+3+q2XzG5VIqSyXWBqR9rxxUy+347CARMGczF5Godd/zqIv0oS/Olk
         VHtnz69D3yECn/7i06UtRe6keq50ejAJMfRCYV/9uPlGz6A+fsgFgcJ48ywRUoh93diw
         NoDE+wH/nW/wWn9DElxv9UFYDKx+nZtpbHrGR9fb8b3Df9c91IHmLp1dEiCpOMsyi0HY
         h/bvt3ji63/CdyJnlMxFg6jkYKQtvbGj6LNQtOZTZuCebMNit8QEdKskzB5kqefGzjbs
         64fRG3yZjC23uEu2uSIsy0zQfNYwfY6BF5XhxmW+bSgm/9N9tt5182bvAA2NuFGXu2ba
         r+xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tbK6AiQt7e6PdsV9+IW2Vc+Mxbm9gz7oGRMwhD8WzXQ=;
        b=WU2Vw9+mR59fgQ0eQhefdP6zhivOWbFDcz2BAOEvJ+3Gjd0bTHH74JJR/PQboFU2mf
         4gpubuh8OHWZnvBpKB4HORxMe9PlqXz8oTNAMe7lCpZjtRS6iVPtNZdmOKH9+C2Rc/pB
         L9qZigwOOfxnaP8PKyLj32zNe5yRAeEgf8DtCMihEAtLT2s8Su5fpMX70ko5Z1DQXjLT
         tuhYtCUCwiW/A2ZwbtYAUO+LjNYDA4Qz11ouJJzDoTfgO03E5r8TSmr+R7gVi73Iv+Dp
         Ov2paD+l+mQ1VrpjWCuZySIgX0Bg4czdTnAeahpDezHxom1pkGBUkLEmhF+ZW6NtKlSO
         6B3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tbK6AiQt7e6PdsV9+IW2Vc+Mxbm9gz7oGRMwhD8WzXQ=;
        b=aT/3CzLFdKHN7C5Y0tKSBqRhUgw5mflgIyieqbgItgPfpK/M5L0w2711txgQpkLcne
         D8jH/FdNRRjNIR51c4QBQ0qVGwFrkKNDwmu2daIcELII4gSYtCcGR019mkQ/atKvQB5h
         Lz04TMDQ5v7m/PnEiOMJS6iVFXhIg5o/IHu/4ZKylZcg9tuyt+9PuxdNAimrKv6oulxj
         XlV/UAq5ugUvkD39ZJVZJ+KE8Ig2V+5jh1P7IIRaJ9bYWTLxefTW2AJ+vTU7xqOEGLhB
         xNHJYLCibVV499SKhu4GwXuuVIarWVO4c9NdGFoKQMxAw5C1EbWqG0OJ+TW/tS9s56Ef
         RhYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tbK6AiQt7e6PdsV9+IW2Vc+Mxbm9gz7oGRMwhD8WzXQ=;
        b=oT0Hh+V/IHQq6Dxci6M05m/Pip2fo8aRBmbiHfaEZcwjI8MdSK8AtM6+DAWxhrHD/4
         ZpTNqSG149QR0yDinZfaySadfsZYmvDiHOKcCz6vaSYTfsZZP6DGCSrNUL6sF7EnIVQX
         2wkRNv7VvpREGxKj+tB6Q9HUXI4ioVSAEsRiDKDC97wh1exXUFUDMu6cRSvTX4faX7AX
         Lv9EFzDwyZWawqFID2vqsLksqSSwYBB2nITZyca/1POCU6sPE03w74SrAKzq9VgrrHHS
         PWCD1b032TS6flnlL8NPkH7GTN71s4Hil9llUIVFoE9TWE78faCR2PHehb6k/t0cXeku
         RA5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OCtFwgS9oUTbaCfuyXYSytZJ9ykmxLptWAEhm9S/+sF6wVXbi
	smEWTyAi3uPYT+VoudPx0ak=
X-Google-Smtp-Source: ABdhPJwEVlFXfIqjAznuBo3xNhnvNximFWb7vxtlCh4Ih+oHqwurQ22DonhOrKVOeulc5vZs9a04jA==
X-Received: by 2002:a25:aaae:: with SMTP id t43mr9951725ybi.390.1611224372512;
        Thu, 21 Jan 2021 02:19:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:af4a:: with SMTP id c10ls1032205ybj.1.gmail; Thu, 21 Jan
 2021 02:19:32 -0800 (PST)
X-Received: by 2002:a05:6902:6b0:: with SMTP id j16mr14566863ybt.169.1611224372045;
        Thu, 21 Jan 2021 02:19:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611224372; cv=none;
        d=google.com; s=arc-20160816;
        b=QOvj+Ib0FjKhyxk3rqfEnUKGOAJnOsQEniDUB01u3alWIpRueY9PREIzdpBNfveBsE
         NJKy8T9XlAk58semTlq++KJ1qOfsOsZXZcsWL00zalQNGoVYGX7FpJEzjSuu/K7+jHNP
         lryHMHAoFeqMIPuS6mxnBNq8OfHBLdvBq4JgXWU14z5qZ9zdJmLIk2xWd1v7d8TMV7ON
         zEOmrX9TSlrJP4zbB+CWOu/m+EygdLdxwFe6actiecY5XZ0ycMu41LMf+q+qkP8dz6oX
         zyt5XZsBlWgbeGMHtNoTpeMLmuatssKEVbjXUuiOXGb9dRkum1IGrIwpjNQ2qavRkfr8
         yuHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=iAUD/Twp93MfKv454uWTkrxBwPv0Xqjc6PYNyIbPYVk=;
        b=AKr8hZ05hf8msRfcG4lOfKyIfnfThdHluie5rH9xgQOBJcOwpTJSEa70NN3lMmDdVM
         wlebO2OYu+SFfVRgBUT9VcgckaHnsUZtA2TRXZ5OuoUdR0FOvrsk+TgiZPL+QpkvbvTf
         kC2D/xIR3bFiWr8ZGzCihMsTflRy0B6ZQUPTHF/NlIMO1MD/+FfacIex8ppaf5UvicJi
         iOQfvSI8y2Dg7vBeGhgjaF2DOM6nOE8vJhn/fNWdjxR6e+BVwAm09RlGtmPEjTMfGPpV
         EI6Gb2LNKsDzLFabpbg1+80BcsZ3H+s2OzOZ8Wof5tYvQjwGXEVmkXMK1b0vLYl7F3AX
         spXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id s187si535872ybc.2.2021.01.21.02.19.31
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 02:19:31 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 36e76576b9b3487e96b940ddce5c09d2-20210121
X-UUID: 36e76576b9b3487e96b940ddce5c09d2-20210121
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 415781448; Thu, 21 Jan 2021 18:19:28 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs05n1.mediatek.inc (172.21.101.15) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 21 Jan 2021 18:19:28 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 21 Jan 2021 18:19:28 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <lecopzer@gmail.com>
CC: <akpm@linux-foundation.org>, <andreyknvl@google.com>, <ardb@kernel.org>,
	<aryabinin@virtuozzo.com>, <broonie@kernel.org>, <catalin.marinas@arm.com>,
	<dan.j.williams@intel.com>, <dvyukov@google.com>, <glider@google.com>,
	<gustavoars@kernel.org>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-mediatek@lists.infradead.org>,
	<linux-mm@kvack.org>, <linux@roeck-us.net>, <robin.murphy@arm.com>,
	<rppt@kernel.org>, <tyhicks@linux.microsoft.com>,
	<vincenzo.frascino@arm.com>, <will@kernel.org>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
Date: Thu, 21 Jan 2021 18:19:18 +0800
Message-ID: <20210121101918.11423-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210109103252.812517-1-lecopzer@gmail.com>
References: <20210109103252.812517-1-lecopzer@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Dear reviewers and maintainers,


Could we have chance to upstream this in 5.12-rc?

So if these patches have any problem I can fix as soon as possible before
next -rc comming.


thanks!

BRs,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121101918.11423-1-lecopzer.chen%40mediatek.com.
