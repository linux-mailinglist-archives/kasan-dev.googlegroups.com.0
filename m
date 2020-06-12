Return-Path: <kasan-dev+bncBCVJB37EUYFBBLU2R33QKGQEV3WEJKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D2AD1F7955
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 16:11:59 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id n123sf6134147iod.17
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 07:11:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591971118; cv=pass;
        d=google.com; s=arc-20160816;
        b=WUXtcU6dgh77ypfnhOReH29YTt7dPBE27OFPOtNtywNEgTTlBGc8K05gbo8eW4PxPM
         tmZs4ulJ1F2HFSuRWreZ+6gNu/svy4g0pq9n+ypWqKq46xsoPYqth1uDsdYKxQ+qzW3o
         o4eUFG+WeDzbhI2Eu/QNlKNu4j4TOtJIihGy+fRUjObFx4ndIY5ZlX+NUG7xozOZzo7a
         4ct4qt8UR6l3mF7PJ4GzzwQr6Nonc2NXSln8FxRpEEbz8bRlRgXzn2O5irNxX3oyiC9N
         NhWYOKJiESNjwsEtP0iORAfFhonvVmz9/IxsCyrjo7fk4wjh83JoTWmVCAay/bvbb7GR
         VEcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:user-agent
         :in-reply-to:mime-version:references:reply-to:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3zi1JXGfgixfa5iNBvNoMvXgvmzlQkHtz6kUozV3r+w=;
        b=wfgz8Wa9bbHYl3qiyp8/FFJKTTfvG6sAGmTg3UC/8HyWKzpqUdqic0CYHAEN68qpTL
         WDMAhH4bXmfpSE/d2XuaZD1IcYgpDOhqEZq2ocusl1gn9sFgtDlIb4+VZlIBXegOJ/av
         YmzKwpcr0TNlE2I+/a2unF5Xhq0kWPCFvQ+uSZ06CWuqgJdLyZ1uiygFMO13p5+HSs0d
         NQkzMIUUYaERbv8exkiu+N6nkdACHFJrjVNhdM24dl6bnztjd2uBWVpKDWUoM3vnPxW2
         07IYoKRd49Kg6RLH3IqebQvfGYcwytsDUL/yhbKiNICDT3nqzUVx0uPCdIs0HDGrVwt+
         auPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HdxrWbL0;
       spf=pass (google.com: domain of jakub@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:in-reply-to:user-agent:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3zi1JXGfgixfa5iNBvNoMvXgvmzlQkHtz6kUozV3r+w=;
        b=mL0G14F9CIGUs8vQQS+TsOvQnFbZFGPcCq1MWaKX+mtdEosPDC9Sff/JZoDsSbwKE6
         xIByEPgLZ+aIoFG77X4C8NEtaHWRBeFF6pvMyqD3IAOuOD2nT/FkHKvVmB6IcUuknGcc
         U3RkflbeIMCG0DsFZ21ZG0ef2a9ZlINCeJhHqilcof5AcMSBbTD5yFbt1SzZC0oZQMn2
         JXBE2jD1T7ZrFb3ma6HOE/4TEqg05e1csYKAWuxxollKaUem0aJnxTw5L9BwIPoUj8RD
         DhSisuy2DJ9yTAvOVzPsXuI6QXD+opY1ZQmx+tF+UltXj6w6gNxJn54CKS5PBhcBgZer
         F+Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:in-reply-to:user-agent
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3zi1JXGfgixfa5iNBvNoMvXgvmzlQkHtz6kUozV3r+w=;
        b=AfERsevsbtF0D7VezBEpngd1TY4Y6Djp7fT9RZBvJA65SO2t0GfSJwlPtX4W0kM0/j
         iWdTGz7mnPcinyQFH+f1L+M06+yjtd+ivd30AHM/EIsO+0HO+uvlqru9d6OcsYe6W8PO
         1wsS8VMDrdX4ER4fXisChQqu4waV62A/QtaeJT09NDdAw7pYd0Iain5pBFN8jC7+mmik
         8uvxmIPHC9+eLDxmonlyPXBG8FVKqkUFyIuug4pf3n9oI1MRC+TTWq873kbSJ/9Z6Ahg
         UQEHVjBFwTvtTkAhQPH9/OSB/88vReFatREmxTS/VvWfpo3K72YemjrRMoKOsYanHVdD
         Renw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Knz6FKRnLcldxgzrWAupvfkO9zx8kbwrLABufVrkYW16K4HVs
	NDNBjEnZzOsVTNTIJOma55w=
X-Google-Smtp-Source: ABdhPJw5S+kcIQVOnlYGaeXibtZwH1Z99ovJp0DCTNK1aC//YcCo6NLjHTboT+aK7FhUlNpUv4o4cg==
X-Received: by 2002:a92:cc4e:: with SMTP id t14mr13815498ilq.138.1591971118237;
        Fri, 12 Jun 2020 07:11:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:3007:: with SMTP id q7ls804400jaq.4.gmail; Fri, 12 Jun
 2020 07:11:57 -0700 (PDT)
X-Received: by 2002:a05:6638:12c7:: with SMTP id v7mr8189596jas.56.1591971117865;
        Fri, 12 Jun 2020 07:11:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591971117; cv=none;
        d=google.com; s=arc-20160816;
        b=Oo+DaVPEg1HQTyCXe72RfOXKfAszD3U9yBq7Up+lADQQk9v0GuJc4nCiEltiZMTELu
         u2uhuhFUCcUsAQXX+PdI1RPOB0tZ7PigXck5iKM2hvXk/ISX5b3cJZLvv7lJWg/+d0P6
         ZtJnb32AfqBcP9oi5zM94iq+XOfsguYd9qWtai7mrXqnyP4+mTORbOIk/ES4tv/w0MMl
         v/Z2Ak5kEMmrfP53ZswnX/RaiP1OhQQYERAhaxvH9XAtUj8D8SL8XN52EFKxKrfuM/Gw
         dac+uM8R+a7HYvGrDvUA/yCB2r//83X+yPXb3BRGEQ2PYJxprfYNfiucTCWoDiU27uhi
         ikTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:user-agent:in-reply-to:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=A1CqnkL/1lZbDatvOY0FnF3Hl8XSOzm5jSr1Rm+FYg8=;
        b=HRK8pSvZZtQFc4rNvv2x5FMFpHjWdD+sn8IvGSss4FjMrC+VlX7oHSNly3RaO5HbCL
         dYZpQSQoBzLyCy8FaFFMXq7Hh3ypiS1p8imtUE8Nhv6dpuNZz2WWbSrwndMg7uoaUGq/
         5MAPlmq6feh0PocIPeKqXjex/87Kci3OCdJ96AFduLSk4e59a1o3+vf8zQtEipO3Faty
         Fzec3p/mt3jjt2DH6yIVW+uRAECxhiKFCmEZD6eZtx67wOCIj3oSKzMgN1l0X59a1Bb3
         4qR9wj0LmCNml+JehNiP+A5Y3qh21fKU4g86kx0D1mtH89qJy2Ugwiv9RLjFQQhRJnUK
         uaQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HdxrWbL0;
       spf=pass (google.com: domain of jakub@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id g12si275055iow.3.2020.06.12.07.11.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Jun 2020 07:11:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-377-IKK3ElYsN-uz5t5_ydEcvQ-1; Fri, 12 Jun 2020 10:11:47 -0400
X-MC-Unique: IKK3ElYsN-uz5t5_ydEcvQ-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.phx2.redhat.com [10.5.11.13])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id DD3C98018A2;
	Fri, 12 Jun 2020 14:11:43 +0000 (UTC)
Received: from tucnak.zalov.cz (ovpn-112-94.ams2.redhat.com [10.36.112.94])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 6A459891D6;
	Fri, 12 Jun 2020 14:11:43 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.15.2/8.15.2) with ESMTP id 05CEBeI9010053;
	Fri, 12 Jun 2020 16:11:40 +0200
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.15.2/8.15.2/Submit) id 05CEBdtE010052;
	Fri, 12 Jun 2020 16:11:39 +0200
Date: Fri, 12 Jun 2020 16:11:38 +0200
From: Jakub Jelinek <jakub@redhat.com>
To: Marco Elver <elver@google.com>
Cc: gcc-patches@gcc.gnu.org, mliska@suse.cz, kasan-dev@googlegroups.com,
        dvyukov@google.com, bp@alien8.de
Subject: Re: [PATCH v2] tsan: Add param to disable func-entry-exit
 instrumentation
Message-ID: <20200612141138.GK8462@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20200612140757.246773-1-elver@google.com>
MIME-Version: 1.0
In-Reply-To: <20200612140757.246773-1-elver@google.com>
User-Agent: Mutt/1.11.3 (2019-02-01)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.13
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=HdxrWbL0;
       spf=pass (google.com: domain of jakub@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=jakub@redhat.com;
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

On Fri, Jun 12, 2020 at 04:07:57PM +0200, Marco Elver wrote:
> gcc/ChangeLog:
> 
> 	* params.opt: Add --param=tsan-instrument-func-entry-exit=.
> 	* tsan.c (instrument_gimple): Make return value if func entry
> 	and exit should be instrumented dependent on param.
> 
> gcc/testsuite/ChangeLog:
> 
> 	* c-c++-common/tsan/func_entry_exit.c: New test.
> 	* c-c++-common/tsan/func_entry_exit_disabled.c: New test.

Ok.

	Jakub

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200612141138.GK8462%40tucnak.
