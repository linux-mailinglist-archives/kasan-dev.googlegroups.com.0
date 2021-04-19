Return-Path: <kasan-dev+bncBC2OPIG4UICBBMFA6WBQMGQEHIIA3MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E106363EF5
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 11:41:06 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id r71-20020a632b4a0000b02901fc8e59f9a4sf5871281pgr.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 02:41:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618825265; cv=pass;
        d=google.com; s=arc-20160816;
        b=kTygTY2uyPeTmrjBep2nD1GNrvE4lDSeni76xaqb0ArMtt4OIvGQOfKCQ+u/+ywuXg
         wnGp6/j3b+DjCsa00DUPoQWiedLWHOd8q0yXBr7BzV60T7qe5f6GM6uba60hmz8kPLjP
         ikR5AFwWU1fzJOFRA/o/pd+tnCtBi0uPdcZO2hf+kYXlx2EVHKUSQdSgae0NFRvtkNfq
         VUrsrBsqbIZAIPnKYQ7feQ2cRgVkDlLKNcma/BSON0bYon97Dipl80kRNXBOY+/JhH0l
         7MDbSUbLlniCpcCCjdogpVoNdUsSpV+I1qmm8YYI3LerS9i5aVYZ/9Xkutu6Pk8uDYXK
         6mIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=H4X6gUj3NzgvVPXpewwGtBDZZsV7V/Cqvx18OhwohLM=;
        b=IvPr/9+z2idxU53DKLyMCZvWu5BDBeKpyfnJey2hAXOpFY7NkpOp1nSPqble/bPFsi
         htrztUSQRst368fbNiFstsAi0PpjneViFOWPDL87igN4PxnD73G85OVlQ4X7vIC3p179
         zm8C+dVY6yOz1U/8QATqRmpROjx15KNsuSUuxKx5WKiydRq4K5q9EfjJZgygFvMm0sAj
         4dIDJ2L72OHoMRsTfuqwBTt1F0xKkQqWkiCEYE0jH3v0H0RPKdKRVITzN187DX2HdEX3
         hVJ0r9K0R/jW1C7dYA0TF84br48brW8TU8fnAubbUzbZAAcnzPLUWZOmKsMtLCEu3Zj0
         zKzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.167 as permitted sender) smtp.mailfrom=hdanton@sina.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H4X6gUj3NzgvVPXpewwGtBDZZsV7V/Cqvx18OhwohLM=;
        b=e94MvvGcaNtNYPnXSOQPgXeg30fMgQmHgrNHOrbDH/7U4klStaO9HhTKXEqLO5k++S
         UDDHit204eroFSOaXfZdfmdH1hw55quSQHbHV3N5gtp6w7z2T+mrikAssCiKWPst9X9Z
         huGdvzoUjVj25NTWWohVCESMFye6sUe9vwP9wC8GMYoUi4jDtQdKZjT/LKrOMLqQjCXV
         +F2g3I5Y5SRp2PtxtribJMzxbeBh65CCNNW+Zue9pxNIhgYqZsxFG0ieEorYiwF2thFt
         DBubFMj635AIKsFphmgBNNa3ciXiWzpwyCz+x8oeO+zz0Vx1mNR2pmwR+nYhOFSnLrth
         Thvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H4X6gUj3NzgvVPXpewwGtBDZZsV7V/Cqvx18OhwohLM=;
        b=smCy/vsvjT9MEhnmBG+t215q0bicmi/mVrgnR93xwsZFKAeGTreCDLYYHoNXBiyV4m
         15W/6F1RToh1jYNIyhqEDoesPznoinW5IJxOAsx0CIDrjVNwCf/2AExFrVTlhSGI4MWj
         /pFAAvYPVauY8UFfn7DZoif84kDe7ibEzgSyzx0F5YWA11kgLB9ePsPUQWv7fH4sH00M
         5kSmO0p/4/CdzgWsNkD6Y2x+14mIHGNyS+ZDxlOVQ7+GhIKur107+OL3V9uw+zdW8NPU
         zdLp9xKhS7f8vVyvr/aFbMEMQB8a4MI2w92RX61Bdu5FvQSK9wrq1bw/HSfPYuiOnTVU
         +FYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Oa038v7lIwYIKFjgP+6KHMgW/V6o6b45+c41uasQUipnnC47i
	G/09cHkP2W4d3yg/LZDZ/dQ=
X-Google-Smtp-Source: ABdhPJw2PzXKDdiK1Jhkbp4bFdu6IVla93ylTgofE7NlG7EKjQsrx0GjzUEu+zMJS1+PtpqAomlX/g==
X-Received: by 2002:a17:90b:714:: with SMTP id s20mr23931904pjz.62.1618825264874;
        Mon, 19 Apr 2021 02:41:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9558:: with SMTP id w24ls6136003pfq.11.gmail; Mon, 19
 Apr 2021 02:41:04 -0700 (PDT)
X-Received: by 2002:aa7:8e86:0:b029:25c:876c:1824 with SMTP id a6-20020aa78e860000b029025c876c1824mr9111369pfr.10.1618825264384;
        Mon, 19 Apr 2021 02:41:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618825264; cv=none;
        d=google.com; s=arc-20160816;
        b=TVf8Pn3yeqtdvUoP3Ian7XHgv2wlOEGoUQMJYICdHPGzLBSu3QSYUtsid6xyKbrUo3
         k2lja15Jt+NTUTJo9dcIbVnGfaMmK4PUA7JPHNnyQqGYJq0JtO7XgvavIbMEEZt0d116
         1baSsC7NNE95OSY3k1Cp1DO9UruwPFFEWJFA5njw28RL8RWHnNmfKUxOYF5plQvDIIOI
         dONeliXQULY05EtXHC+BElyMSJh8S19y9HV7BdJ7abz6kymuluJPq7o1EmADy+1KJ5Zi
         EbZh+4EEAir/fsNk+lYTB9fgD0U/90O6TZFEdr8dhACglsao4qXu7fW7fB1XtAirz8ar
         uKWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=adjhODnwBP5+dG4zCU38gkkHpRz42oK3fUI6AWlR45s=;
        b=EMYqlLHU3NuMj0iDwhIUkK+7S6k71/7U1lp+z2Mqkve3AMVsVBxupoFgXeDlyPiO+G
         rTz6KnEKDywtqVMHRFAnVPWPwMyCsWAmakLYUviCvO82rRkc2zauntfUblAFvXj7U5IG
         QAyk3Vo7mN/KssPIvE/DQb/iosNHD2+oN3Dh497jniOuUfor+nhxCIj6fSLP9FDuBjlJ
         Y2us+gnaMvownFUTGz+Ifw1PVoj0ehAkOU+XV65WmFVZmL7CG7ZmZyF6/ZUxswt8Fq2N
         SsyYjw+Hq3AYgbno+sA4Lu/L1NFLhNVyIWf4eqeH3WZanTkM4NTTT/F17B4VIDeUFhEB
         EeXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.167 as permitted sender) smtp.mailfrom=hdanton@sina.com
Received: from mail3-167.sinamail.sina.com.cn (mail3-167.sinamail.sina.com.cn. [202.108.3.167])
        by gmr-mx.google.com with SMTP id q62si597542pga.0.2021.04.19.02.41.03
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Apr 2021 02:41:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of hdanton@sina.com designates 202.108.3.167 as permitted sender) client-ip=202.108.3.167;
Received: from unknown (HELO localhost.localdomain)([221.199.207.228])
	by sina.com (172.16.97.32) with ESMTP
	id 607D50250002C0A8; Mon, 19 Apr 2021 17:40:55 +0800 (CST)
X-Sender: hdanton@sina.com
X-Auth-ID: hdanton@sina.com
X-SMAIL-MID: 355996628851
From: Hillf Danton <hdanton@sina.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org,
	glider@google.com,
	dvyukov@google.com,
	jannh@google.com,
	mark.rutland@arm.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/3] kfence: await for allocation using wait_event
Date: Mon, 19 Apr 2021 17:40:44 +0800
Message-Id: <20210419094044.311-1-hdanton@sina.com>
In-Reply-To: <20210419085027.761150-2-elver@google.com>
References: <20210419085027.761150-1-elver@google.com>
MIME-Version: 1.0
X-Original-Sender: hdanton@sina.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hdanton@sina.com designates 202.108.3.167 as permitted
 sender) smtp.mailfrom=hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
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

On Mon, 19 Apr 2021 10:50:25 Marco Elver wrote:
> +
> +	WRITE_ONCE(kfence_timer_waiting, true);
> +	smp_mb(); /* See comment in __kfence_alloc(). */

This is not needed given task state change in wait_event().

> +	wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
> +	smp_store_release(&kfence_timer_waiting, false); /* Order after wait_event(). */
> +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210419094044.311-1-hdanton%40sina.com.
