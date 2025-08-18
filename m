Return-Path: <kasan-dev+bncBD66N3MZ6ALRBN6KRTCQMGQENP3GZDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F8C0B2A315
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 15:06:01 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id 71dfb90a1353d-53b1757b54esf8305879e0c.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 06:06:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755522360; cv=pass;
        d=google.com; s=arc-20240605;
        b=IEf/WbBEJccHoG4wMGlX7Hih/+eWktIiCW075xqDgCqDOItOqkPDpeJ48uH+8j/fE1
         ksBFEixmTC6eon/1FPRuLNlkZRRV952QlBh/l2gNU2YQVds3bOTU9NC+yA93l3uGMNfG
         bveiFWEX1UGssTnGZAcV7upYW1ay7SW1SlrZFOvf32jbtFVCyzRynytcyH7vvgMw8CL9
         whk4aXYd5OUiw3t7aaMq5dlo9pPqY5FeVbRMVZ5PS2DwyDb2pAlR/Ezv9/GhMoRFe4ST
         NnsNH6ppYMWsyvRZmw9yfHO1/T9/5lg1sS25Z+OQ/3loVtM9zfXEEPSvUOzr8lW7vq+C
         HsqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=0hRvYITAc1uWrOVdDKFNC0BUZ+9wp3JCaTV8jmv73g8=;
        fh=1yAxaQ/C+UWRcQdVxQRNmlPw6KMdlGhDCdDZSC+XC5w=;
        b=OsgkAm6/mp9j2aON92eZ5hBzWQ+BjexYnXUoI4N++SFfvflbfTOa1W/6KYiijf4Faa
         ST7U2OiyvY/5fpenorFdasD0ltVFbWwqAEWOebfRZrbGcjn3G3dU2IFC+3OY7Hx2J4WP
         fMGYJe5vpI4Y4mNIlKZxgkCc4dNWfK2D95HeEnBMAZ3JqK+yNmFeE//Cm5+9w0E5t5Fm
         WaiS/8YNoe0/j6U4YdJiG/8I8W3QrznTgpddsU/7jDWmgdW0wT8bdJUmKvmMwmKVstiz
         lp0lfg0qHIK4B5FGWkIHCpPJ5FkmGnyDXn1M77XFSR4ezFK9kIC8nHE3xzhVuuqe0rTM
         +G3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=evxV2HZP;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755522360; x=1756127160; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=0hRvYITAc1uWrOVdDKFNC0BUZ+9wp3JCaTV8jmv73g8=;
        b=W9AKdAy1Hh6xkRiWJjC7WsAhJUFLIiwE1Kqri7hdbzdwOf1gkEx9FsZzZe/n0OASOU
         QUvDdnQdXuqA3jMLmkiq5039/BJOeSzRCHrSzxG602A1SAYmSUKebk62jjr/XSE6xy1U
         CXVhxm8I1hbXXTdOmuJa9Mijrrt9nWrzP3mfRI+NT7GQOvvyKAF/D8QfRtqA1kWtV98W
         l+ibJDu9aqB8SBPyUyPdxcEJlPqof5zkakjO8TcOOrqBc0f4nigejdQ+PtdHxtZhJVzc
         ZfISjhc8DlkE62zE1TPzHxUcCQi0/RfCCcIbF83hdsjHNjnDTxGK81jqWn6rMht99rzH
         0ydg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755522360; x=1756127160;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0hRvYITAc1uWrOVdDKFNC0BUZ+9wp3JCaTV8jmv73g8=;
        b=rBGwaLyS52eJundk9Pq232DkkNIF280OzhPgtPyXzGjgomE/ghxZhYY6RS+B40DiQv
         zz2FWzNSPFrPrdfnJSqxswRLZ63WyGbHUJqipzqAS5RmfYMe79ju5KISlzDgfWZJ/C/T
         AzI+qqiazc10gxsEVgeAzVvQnJ2L/c9m8LDJn2+pmkjRKZHfQ+ZqlIKu/pXII8u1Uxz6
         JNBZPERBRZgztp4T/cnjQm8A8QpbkR0vDK9vP4h6rz/OBTTGHqkPHwDQhn31PadHogZI
         SGoCCO5l2Yo0dAL6To+VJNOJzkQJpEQRVj481et3TCO0p8d1+Hkox7bSPl/GtmHEkEDm
         JvKA==
X-Forwarded-Encrypted: i=2; AJvYcCU9z4ym0C9JQZpXasQEcCnQ81MSDnQR/fx2YlZrzIfLZExIm0cMmZt2eV5LwgjRZzaiXewq8A==@lfdr.de
X-Gm-Message-State: AOJu0YwQ05B/Sf497F7Kyfh+LKAGE7JsUiFW4IGweeVtuRpbYomUV1Yg
	DQ+ZPWu3Qz0HhSlif+De2lB7dEHulZe7YOXiZOGuWAbBK0L74PjO3ckG
X-Google-Smtp-Source: AGHT+IHYUV/q0a3A6kYAgHE6X1jSqpXg9L0DbonwvC/nUHmkhUQma37ZRRxb2WMnOIoGu3gEppS/2Q==
X-Received: by 2002:a05:6122:46a9:b0:520:64ea:c479 with SMTP id 71dfb90a1353d-53b2b911006mr4306960e0c.10.1755522359763;
        Mon, 18 Aug 2025 06:05:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCvfz79NSqtczUaBPt5JCgda00mWNo7dtlRE7L0Nv5Xw==
Received: by 2002:a0c:f097:0:10b0:707:4335:5f7 with SMTP id
 6a1803df08f44-70aabf21027ls41987006d6.0.-pod-prod-09-us; Mon, 18 Aug 2025
 06:05:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDdrzyu9eL6hnhfxTRVGD7paMK+w8KAqArIZJv3bOciRJ+XNeJofaQOMjStRb7ON3dTlKSZHXMHRU=@googlegroups.com
X-Received: by 2002:a05:6102:1622:b0:50b:de14:ab9 with SMTP id ada2fe7eead31-5126d6f3149mr4479276137.27.1755522358579;
        Mon, 18 Aug 2025 06:05:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755522358; cv=none;
        d=google.com; s=arc-20240605;
        b=DwKPofQjAhVKV5XJsBdccNGEKhnLqKwUzgEuGdEVog/Db5WMjy1t22q3XMp9jWi3Yw
         3QrgdU1Y/hqs/KNDcR1CM+dz7kATr96J92tL1JrbTO8wsjOhrJW5KX4ORnPv98DlTlJy
         SYroW05WwCg2JbrcPFvffQjTSUoHogz2DwwPaaNnYO1PbD84g/JBldalp6VWGPcUgtu7
         0NIy9/SLfQVNdHiEdDg6smeu4QgaOKrYtwDJECjkOUQ0L+Rx2K+IyS441YWNj4RgVR0X
         +95FRD6AUhpwmFKIOVHlsrYkalVl2q/nkwnzm5TIoejNGTTC5XPgO+10DfYbyZJYAs6+
         Qo+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QyzL3GSkiAQfeG6g6YvIMRozhZr0+dfb72trcSazY0Y=;
        fh=keGaBf6xvmPht4rsYteysR/AYL2BK4ITc+AARhqx/To=;
        b=Hek4292bAvULil5ix7wvBMP6zGbwd+NNdDnbQO5Gr0GcmS/1kKDBxwDj/+rRTjMVEi
         90nb5i+XDU4ex8DIE1yYuPuVVcvFLiiC/se+A3AJUmXAspqVuPrEfN7K4UcFJZouWVPG
         WqdrAkbtxuSj4H407mMAYrO549TTnMgIV/zNe16k6q/8NPtEZmIlcuJAFMuKhhe71JNM
         DMmcF+Nw2vbMhuD5K1oTItQ/Zwc9DzmQCIAPasdSlU7GQ6ODXV6Zt9ZqNqlm7lxUSb0w
         B5aj3fcWH3Y4uf3KZOp0fvL4wN5UrWd7MJdmTc5vZuDq1qkWsfU8YHCN7KiHSERp6+ix
         HIrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=evxV2HZP;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70ba9029953si2687136d6.2.2025.08.18.06.05.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 06:05:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-284-XlWK2UtwMF-ScKJ_-M8afQ-1; Mon,
 18 Aug 2025 09:05:53 -0400
X-MC-Unique: XlWK2UtwMF-ScKJ_-M8afQ-1
X-Mimecast-MFC-AGG-ID: XlWK2UtwMF-ScKJ_-M8afQ_1755522351
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5711A19560AE;
	Mon, 18 Aug 2025 13:05:45 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.44.34.24])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with SMTP id 5D9E6195419F;
	Mon, 18 Aug 2025 13:05:38 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Mon, 18 Aug 2025 15:04:28 +0200 (CEST)
Date: Mon, 18 Aug 2025 15:04:20 +0200
From: "'Oleg Nesterov' via kasan-dev" <kasan-dev@googlegroups.com>
To: syzbot <syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com>,
	David Howells <dhowells@redhat.com>,
	Dominique Martinet <asmadeus@codewreck.org>,
	K Prateek Nayak <kprateek.nayak@amd.com>
Cc: akpm@linux-foundation.org, brauner@kernel.org, dvyukov@google.com,
	elver@google.com, glider@google.com, jack@suse.cz,
	kasan-dev@googlegroups.com, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk,
	willy@infradead.org, Eric Van Hensbergen <ericvh@kernel.org>,
	Latchesar Ionkov <lucho@ionkov.net>, v9fs@lists.linux.dev
Subject: Re: [syzbot] [fs?] [mm?] INFO: task hung in v9fs_file_fsync
Message-ID: <20250818130419.GD18626@redhat.com>
References: <20250818114404.GA18626@redhat.com>
 <68a31e33.050a0220.e29e5.00a6.GAE@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <68a31e33.050a0220.e29e5.00a6.GAE@google.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=evxV2HZP;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Oleg Nesterov <oleg@redhat.com>
Reply-To: Oleg Nesterov <oleg@redhat.com>
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

On 08/18, syzbot wrote:
>
> Hello,
>
> syzbot has tested the proposed patch and the reproducer did not trigger any issue:
>
> Reported-by: syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com
> Tested-by: syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com
>
> Tested on:
>
> commit:         038d61fd Linux 6.16

And trans_fd.c wasn't changed since 038d61fd...

Dominique, David,

Perhaps you can reconsider the fix that Prateek and I tried to propose
in this thread

	[syzbot] [netfs?] INFO: task hung in netfs_unbuffered_write_iter
	https://lore.kernel.org/all/67dedd2f.050a0220.31a16b.003f.GAE@google.com/

Oleg.
---

diff --git a/net/9p/trans_fd.c b/net/9p/trans_fd.c
index 339ec4e54778..474fe67f72ac 100644
--- a/net/9p/trans_fd.c
+++ b/net/9p/trans_fd.c
@@ -666,7 +666,6 @@ static void p9_poll_mux(struct p9_conn *m)
 
 static int p9_fd_request(struct p9_client *client, struct p9_req_t *req)
 {
-	__poll_t n;
 	int err;
 	struct p9_trans_fd *ts = client->trans;
 	struct p9_conn *m = &ts->conn;
@@ -686,13 +685,7 @@ static int p9_fd_request(struct p9_client *client, struct p9_req_t *req)
 	list_add_tail(&req->req_list, &m->unsent_req_list);
 	spin_unlock(&m->req_lock);
 
-	if (test_and_clear_bit(Wpending, &m->wsched))
-		n = EPOLLOUT;
-	else
-		n = p9_fd_poll(m->client, NULL, NULL);
-
-	if (n & EPOLLOUT && !test_and_set_bit(Wworksched, &m->wsched))
-		schedule_work(&m->wq);
+	p9_poll_mux(m);
 
 	return 0;
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818130419.GD18626%40redhat.com.
