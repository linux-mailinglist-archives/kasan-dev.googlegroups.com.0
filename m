Return-Path: <kasan-dev+bncBCKPFB7SXUERBHPH26HQMGQEHRNM6SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 363414A3335
	for <lists+kasan-dev@lfdr.de>; Sun, 30 Jan 2022 03:10:39 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id d70-20020a6bcd49000000b0060d10445eddsf7398084iog.13
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Jan 2022 18:10:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643508638; cv=pass;
        d=google.com; s=arc-20160816;
        b=C4P36SrcDV1oc4JjDvMsj+etsul3GI6/uc7RPbfFeTysFlcc/6Jx1dGvfezq7Irqwf
         YXr3LgNz6+3ZVRmhtbSq4D4G1KfWxkbulPmqJ9djQ9D9tbtZISTLdrvAHo5nnjQkL+VH
         f2gHqGzcqkVPVq0GK61SuBZIvJuIlvk+scFrVg5Q09qotHIQ5si0UQWH8RRDKYLC5kSy
         sHSbLJhf34QXqkmLy9dbMTr+QPMWeyd+xxRR3CnJb7i8mRp0FdcyznkuAIsRl6/4qD8C
         4/UEs4ohILKs/UU9IyQfgbe9YOa5dJvJgNOZragGU+9ZCOZTI2Wl2Wk+LPeJrpqSwOL0
         UaTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=DvI+vGEnQTvPV1YfmWt3qKgNGCUpXb1S5DKPYJLl6xo=;
        b=bZ6mHO4XuoJ/u2twuuVZdCdjAKbTcyn3hmrsCqnHOvdWeJOENE0p6LdYCjgr9euE+o
         BocK1QhXrKssJzDwdQsWOwn5fDOYFMrACCdHAkrUMp5G+zK6vYQ5ueu2Bq6xjI5Q0n9V
         BsLrYkluFI1hQquzYuPNQbzhCLTHZpl6bwXtundKWHJCqI+LyIJeZJZy97+4hZSlruYQ
         eJny/CnCYXTq2jVGjfWAiKO84lg+jjK9hgA8COKfOBJUOG36rllIX3zRbpbcgQ8ilnKG
         JoZkwLNyrrL6tnCv8aNlyZYxVJ5Y9wHI5FFmvjOkx8pxWkyfKbnQiNfZALQ28cFhIm2P
         Kq5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IwxTzJnY;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DvI+vGEnQTvPV1YfmWt3qKgNGCUpXb1S5DKPYJLl6xo=;
        b=gcAimwfWX9YcH9RhIO81Vm0OQfTa4tgASvQvx2XGkkX8tvl1R7UIJrdlLLAUFrs0Pq
         LY5e2rXYk4LuvgCo6QV4ONjXjD3Nt48fQ5r4REYmlraC0xYPRiakVymDr2uNRB2vl0BF
         rnNPAi2n/8eaLHFK9G/OSSG1x+ema0EcQUPY7R+E6NodgLSulCVcGrcXJVb3Brrq9U1v
         x8wwR64NxmTQuHO2rW/AKXED+ayQfnIRkWNHMrE0qCuEWvRsWcUagODcvNNf6tIMezPj
         k+kAwOemlIyZSWC3Ev5lAVH2sEzb+T10evQNvKr5JylJZjI1rgLbPSrF9IzGI2cljRjP
         9RzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DvI+vGEnQTvPV1YfmWt3qKgNGCUpXb1S5DKPYJLl6xo=;
        b=2PIYBlvk7l3FcKPMcvVnZsP7HiF9S62UhIgIiIcnHTAo6mATluQAEF4KkyuIkBreXf
         gPTp7Y7uo6txIvXoFbf8QBGJSEc6dapcgGnBOY5DMm1KHO4aokLcZhEXQJgR1ELG/umi
         BZ4f0rbAnIabyycTqkkUzU9NRLqIwary2iBrZOtxBHIiZq0zdaaeYCbgJQnYBp0TYDWb
         aiiFJqdwt4M9sr4Y3NtlOHWr9aDbniNCll2T+ahO/oKu3/r0qoqNUWDojf644hthn+wm
         cz7MDu+OM7kdELjA3jZhCRVQXonRrY3Ia6i58Zb50LItWcSCIiUbCY1N3DfUS1tuju6A
         wMug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gXffhnheYvaftTnkBc96ZKAsLsk+2Nu5yFUJEQqLNfaafLjAK
	kRCPwfLpLv9WpZf9wdQv5W0=
X-Google-Smtp-Source: ABdhPJwnkJCCY/hI931s9dKmMiqzpOo3qC93/FxGdXyZam4RcDnbCypDXUt2W27qL705FRdtdpgxLw==
X-Received: by 2002:a05:6638:24d5:: with SMTP id y21mr1445906jat.115.1643508638044;
        Sat, 29 Jan 2022 18:10:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:d0a:: with SMTP id q10ls2487307jaj.7.gmail; Sat, 29
 Jan 2022 18:10:37 -0800 (PST)
X-Received: by 2002:a02:a19a:: with SMTP id n26mr8334051jah.129.1643508637747;
        Sat, 29 Jan 2022 18:10:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643508637; cv=none;
        d=google.com; s=arc-20160816;
        b=ttJNW/1RFY4uT6kOkC5Y8Nyw65dCJImbtXKFGnd8ZTCjH9gdekDewlzf3dlkBTl6HN
         Uzh/N69+QVG5tMVmjulUtgxmziVNtWsudToYo8FSn0/+xJ1ne2uEtQrSU5UEVpUQ0LYt
         yaRr4UnkyxxxItXX9bJiw1KVvkmoqEI1+iZ3HIGLJVS1SvjggTNzvgW9Fa4a3tR0lyJ1
         LKRG3EAm8IGHWM2BsJxNFlEdH+HUqgzYnaSdB0x973jlhhDg1xkbJjgBgl+3efbrG/gg
         ALT3Pn+Zx8z1lHnyRd0f2gT9JIwk/x671v/IKW7n+ZfcmfLf64kw6SJUH3AvVpSO4yZ/
         jwMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xhTMfyrjbAbtJcMYDK7fzUfXvPUd309awCDdI/pLbrI=;
        b=Ies8zCc1N6r3GpCh/wNKd4xmMhrhsOrBee7Ip+wLHfKzTu3OugQIlYSYqLKpShHEKw
         yBGB8EVaQa2OnUVVSuLtL9abaDolMQJQReeoYeochiW6Szc93TwAkF06QBx8gFCkwtTU
         EnEUr8ytWAsFL8QD7069qGrZ5Gs1K+MDGCB/Jm4HLiRCf0ZwGk1xHhW8OAnBp9t/doy+
         WS1D/r2oIjkuc3QYXbrTI4xMdEya19pjuot8cgqfrUnGh1xjJIDX7vS5CSEBMbJ5vUhz
         hGr37/e9rhvRjlAbc6cLf5H32z5tdX4Q5WgwKP8Aq1mNKX4lMwFDlmOXDd1pkQ5f9KAh
         CnDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IwxTzJnY;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ay13si1269032iob.4.2022.01.29.18.10.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 29 Jan 2022 18:10:37 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-275-Cw25cyrBM72GK8TGlt1RNA-1; Sat, 29 Jan 2022 21:10:33 -0500
X-MC-Unique: Cw25cyrBM72GK8TGlt1RNA-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 4689D8144E4;
	Sun, 30 Jan 2022 02:10:31 +0000 (UTC)
Received: from localhost (ovpn-12-238.pek2.redhat.com [10.72.12.238])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id EDBDB5445E;
	Sun, 30 Jan 2022 02:10:08 +0000 (UTC)
Date: Sun, 30 Jan 2022 10:10:06 +0800
From: Baoquan He <bhe@redhat.com>
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>, kexec@lists.infradead.org,
	linux-doc@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/5] docs: kdump: update description about sysfs file
 system support
Message-ID: <20220130021006.GA29425@MiWiFi-R3L-srv>
References: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
 <1643370145-26831-2-git-send-email-yangtiezhu@loongson.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1643370145-26831-2-git-send-email-yangtiezhu@loongson.cn>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IwxTzJnY;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 01/28/22 at 07:42pm, Tiezhu Yang wrote:
> After commit 6a108a14fa35 ("kconfig: rename CONFIG_EMBEDDED to
> CONFIG_EXPERT"), "Configure standard kernel features (for small
> systems)" is not exist, we should use "Configure standard kernel
> features (expert users)" now.
> 
> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
> ---
>  Documentation/admin-guide/kdump/kdump.rst | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
> 
> diff --git a/Documentation/admin-guide/kdump/kdump.rst b/Documentation/admin-guide/kdump/kdump.rst
> index cb30ca3d..d187df2 100644
> --- a/Documentation/admin-guide/kdump/kdump.rst
> +++ b/Documentation/admin-guide/kdump/kdump.rst
> @@ -146,9 +146,9 @@ System kernel config options
>  	CONFIG_SYSFS=y
>  
>     Note that "sysfs file system support" might not appear in the "Pseudo
> -   filesystems" menu if "Configure standard kernel features (for small
> -   systems)" is not enabled in "General Setup." In this case, check the
> -   .config file itself to ensure that sysfs is turned on, as follows::
> +   filesystems" menu if "Configure standard kernel features (expert users)"
> +   is not enabled in "General Setup." In this case, check the .config file
> +   itself to ensure that sysfs is turned on, as follows::

Nice clean up, ack.

Acked-by: Baoquan He <bhe@redhat.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220130021006.GA29425%40MiWiFi-R3L-srv.
