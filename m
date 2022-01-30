Return-Path: <kasan-dev+bncBCKPFB7SXUERBBHY26HQMGQEYMTXIOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 260254A335B
	for <lists+kasan-dev@lfdr.de>; Sun, 30 Jan 2022 03:46:30 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id o20-20020a656a54000000b003441a994d60sf5991133pgu.6
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Jan 2022 18:46:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643510788; cv=pass;
        d=google.com; s=arc-20160816;
        b=cCi7qRIheKDk7qc7OLDyWHrIRaMKtbw7/Uxqa7CsP30hxqVC/r8D2S2l4r2wa42KyL
         oOrObo3Q7rvFNsa54rzD6o3OjQhrrJnhYhkdExT662XvcPl3xMD2e3nwcLoWTpQC6glr
         h3OCfo8rBI+XoEtBDG+6s91ecm3jb4CLIrwTaFSVtWRxTFzYW3blZLphtQ9jiAqOWnAR
         rmVJ9mSY5o6+OWjO7l7tnynMlGpqY9Gq8X8R3XMJ8QIt01LggQPBIasBfm4KaFEcn92Y
         hUP9xG047iK2nlAhbnlPibmnayV5lDhhI00yGovZm6pkyLmpWqMXcoGOQd7DzHxdv9wu
         0wCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8EOBjAZ+r2Y73r3JORRhGTnKcCIlR5jGvtACC+ri2k0=;
        b=qcpaBuJd6O5oiolx5FRUQuqYqpv7iCRcD6B1TjndfZWBYTyuiqy/oq65soKjBCacTZ
         zsebCxkK46EKWT5NnJZRsvIyEW48Y0HfWQl0U1D5KjoTI5vCSrbjPXODBtw/WJzgDXa7
         4oqtUY3FYdsbm1Rlr6FyT+Ba9FVyLw+DNMWb/QGXxLwOgzOmFtLjneMt5Knjy4rEWSus
         q4ao8OXlgfan8cCet+kCkvIxc0Oxe3L/N8kVNK8xufQMDKgk/mYogTqO5UC4Swo0qvJZ
         D5JXx6EXQu57TwAa/sPnJOgr3Tvy1iHShmC0quVHQ3R5ewUqCS2kNjOKPmDg6Zgn6U00
         6FuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EacTNH8o;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8EOBjAZ+r2Y73r3JORRhGTnKcCIlR5jGvtACC+ri2k0=;
        b=RIqCsvSyQ59WW6P2GdaOGC78kUQBOv7LFYvg1IDEZc7oDfjw4WaMEFQydvr+zGFkCE
         0Ciz0WNznykyEjDYJMVmFJ/ITLEyuqpMADvsvLzTIuRD+KlU706J8fCko/X67+7h22IN
         9qwkTdL6G0AZYBrOZM9/DMcbBnKoCpUCNWkoM4IAoLZOhKpi73rm23vZg33gTIPnRr33
         eHGoVyvGaUTE9lC/vCh4MpLg9YKETvceHG0YtIQkKHS9+R6WPbhi7FKoS2RCgzikeyAb
         +Oo/j2/4mt8zg/1N8aqHsZEeIH89ch534vp6vB6rRmjp0+yPaVup7y0qjPZbTAW2Qxtm
         CCoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8EOBjAZ+r2Y73r3JORRhGTnKcCIlR5jGvtACC+ri2k0=;
        b=lzDmmIkSRdDNeu2HF8mNzZKU1ye9ednohnzcfj3DdfQU93MJ8c15L3NQ9MGZM0uYkB
         dKb/XEHNyFg8L2sXjdWCs2Fd5C4Riko9p3aRu1Cw5DXaruGMilB34xIp+5uGsb7TODHd
         d5yprlFBm83xBAB2Ctz0VQN/hH6eDxP4a4StyJUrsUzNXCbKkogPUdx+rW86L2nUUEYe
         bSpdJq9XsFkqCN3qiWnECx3nBiUutGOfnpXL01hGITlSoRZpCj3alv1o0ULYsquuy5SR
         9n1TrJ7/1jFulFiurjyJJ6zSwf0mtgVBeB6J3xz8aT2SwANRq4WaIxUC2tvH4+HGMbD+
         0XQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Xdwx7PYbQfMUcTQfthry7UZMlUpPRBnBGUA0PUyMIXBNT/zR0
	xfHKHOwdpUQm8v07aHhHDnI=
X-Google-Smtp-Source: ABdhPJzfmISew4+6NE3str4BVAHrKyTeadTYP6CsYRiKK8UZKXR71KxffCspgBiYx6oi091qkeJnyw==
X-Received: by 2002:a17:902:f681:: with SMTP id l1mr15302236plg.169.1643510788572;
        Sat, 29 Jan 2022 18:46:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:b42:: with SMTP id p2ls5428540pfo.4.gmail; Sat, 29
 Jan 2022 18:46:28 -0800 (PST)
X-Received: by 2002:a62:d14c:: with SMTP id t12mr14638421pfl.30.1643510787936;
        Sat, 29 Jan 2022 18:46:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643510787; cv=none;
        d=google.com; s=arc-20160816;
        b=q6yxzLtNrY8Xp7aoNfNOQK69eyvrLl72hYIiLUumrIKzKyo0qqSudrj3h4r/WDNQhq
         6t2Iy57lcFdPfmMJi54RjVn7sf6fW8uhO+QPjH1QZdEcl/2zxwjfwxPWEVz+PXSn2wLv
         jZQiz3Sk/yiahwVeYNgJkfi5FxK5RrYXxqXRJgj7O9sm1nsvlPZuYRbPIasuG7Y/NaBA
         0vRO7Ujy15TpuqFL4//oyQR2me9VvJ2XkHj0UyJ74xj3XT2hORSBINBfgiusNl3BzuVk
         bfnhUVNte2h9xtSR0KOJTAb09GKg3imnSMmdDbNcoRCk534HanuJKVxGJSHK1FHE/+ON
         w/zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pcOcmEb5ngGy0dZAQ9mUDW+ZAjVj+zk/0lR2PgFjLiE=;
        b=pi4UVFsBNIg1C9V3PZvOqKRXqA/4ihBplDZEMzWc4LFxtw5zJzXU7dx+52fsVXlKwI
         Kri2MCIn8fkXQKGLi0KjXxbIP6n0cOkZS6ztCpnbpm+dlvMCC96A/2yy7V1QPoZK1laZ
         Kni+3g0pHZoMa+Gcgc29SwgTm52yq4QY3Sjvb1EacmSx5YHV1TzrX6DMBJSU8uPsNgzM
         QPyZzRJWDLFd+DEOXggdqIzLty2aFtnqhVP04Numct0SwKhoKuSzK8LcT7vrcxqhz7Il
         nLgWCLQb+Ytb2k2kVYBoOaMS1iU6jnlslCoQ9a16wIAjpVb0ElF+u+nUx8rSUwsnAJ8u
         VgUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EacTNH8o;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id gd22si369708pjb.1.2022.01.29.18.46.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 29 Jan 2022 18:46:27 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-43-_VSw3NT0NqiU6JSdBclvyA-1; Sat, 29 Jan 2022 21:46:23 -0500
X-MC-Unique: _VSw3NT0NqiU6JSdBclvyA-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id E504E1F243;
	Sun, 30 Jan 2022 02:46:21 +0000 (UTC)
Received: from localhost (ovpn-12-238.pek2.redhat.com [10.72.12.238])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 1C83412E34;
	Sun, 30 Jan 2022 02:46:20 +0000 (UTC)
Date: Sun, 30 Jan 2022 10:46:17 +0800
From: Baoquan He <bhe@redhat.com>
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>, kexec@lists.infradead.org,
	linux-doc@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/5] docs: kdump: add scp sample to write out the dump
 file
Message-ID: <20220130024617.GB29425@MiWiFi-R3L-srv>
References: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
 <1643370145-26831-3-git-send-email-yangtiezhu@loongson.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1643370145-26831-3-git-send-email-yangtiezhu@loongson.cn>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=EacTNH8o;
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
> Except cp and makedumpfile, add scp sample to write out the dump file.
                                      ~~~~~~? You mean example?

I think we just give example here, but not list all cases. seems
adding scp is nothing bad. Anyway, except of the concern for 'sample':

Acked-by: Baoquan He <bhe@redhat.com>

> 
> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
> ---
>  Documentation/admin-guide/kdump/kdump.rst | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/Documentation/admin-guide/kdump/kdump.rst b/Documentation/admin-guide/kdump/kdump.rst
> index d187df2..a748e7e 100644
> --- a/Documentation/admin-guide/kdump/kdump.rst
> +++ b/Documentation/admin-guide/kdump/kdump.rst
> @@ -533,6 +533,10 @@ the following command::
>  
>     cp /proc/vmcore <dump-file>
>  
> +or use scp to write out the dump file between hosts on a network, e.g::
> +
> +   scp /proc/vmcore remote_username@remote_ip:<dump-file>
> +
>  You can also use makedumpfile utility to write out the dump file
>  with specified options to filter out unwanted contents, e.g::
>  
> -- 
> 2.1.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220130024617.GB29425%40MiWiFi-R3L-srv.
