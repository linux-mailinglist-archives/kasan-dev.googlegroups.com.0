Return-Path: <kasan-dev+bncBD66N3MZ6ALRBXGGRTCQMGQEZYYMWKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E817EB2A283
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 14:58:05 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3e66486a1dasf17672215ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 05:58:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755521884; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cc5yu2ORHwH48EmDchwLCkGYVEME/euTe3mHOdw/A4DaYmKZd+zQhGiH9fwR0EB8dD
         LrimaVlRCotZ0+1WdMPjEGYZ7UaFLoJ0FzJdn3YTX3amk7MmvV73ohf8cmBxkAXvRExH
         z7PANNW7hZO2dMra9yaX0i8raF6WQLmzzdwHQtqT3/79zjtTiF+MeLmMgssQ7LVYEz7x
         ZcWVyA7VlUfjMMr9vz7sTIt4P3CoBhi/Do6fz89b8hUDewu2yMX084lEesiVifPetCZj
         r8mdjZ5eh5fL/3+4I5oq9Ee7uPWzlvblUSSHCu+C/msYZtWP2RzIiF1qHE5Cmm5QSrqK
         K0nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=lBuDQhj5+R192liT2+kUPdQ70rPXF7PgMoZ2/tcl2NA=;
        fh=Xj8vzDSF6nC83+rBhnh4Epj3zELcHSFVuVSQYxH4/Wg=;
        b=K9xuQIyPMBfZmnHN1SLt/0+C5Td69rpEqYEVRoXYKFu/fD7HwT1rdhPljn2rEdVZ3U
         nJQXiktbl10kfBeTZiXUTksY2u7wBGUyufHZVsllW6KhvTdTY6aCX2H1k0p4AfF0LXZU
         UCwr/yQnjmxs+DDGuyKnsPVCfBl/+zj7OefQcn3uol10LrNIR/mQxDZWmdUi2kgj8DSE
         yxpfSVWUh9G2zSp8rVTmK5fAziS1SMvu6Me7q8gojedsAdw8FxNp0tcLnhdLel7D+UJ7
         fRk48UBG66l/Tmi+25xSITVsMmA9k9+Awtc4Ez+iYl1axpVuWGQgRbeI8woEkFQjSuqu
         VQPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gcy8JlzU;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755521884; x=1756126684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=lBuDQhj5+R192liT2+kUPdQ70rPXF7PgMoZ2/tcl2NA=;
        b=wpplFidkSlAi23JLVMG3XnwRysTc6jE7UQe16D5b285SUd3Rr5TGsUV3+XJ/Hpp6K9
         f9MtdWX+wzH6IEZsBd0OZHF40WQgCWdbawMfbUpQNk64gXkVAI+iPWQoRjCnhQ6pTHGw
         LefWURNPLe+D15PLyOOrTLTKvefnMDUd0BBdK7Os+9pK9c42Vh2PrKmgvjd7tTf3PqsX
         J+retT1W04aYTD8Q20pwvZL+GhsvdYUlqLrizLcFyTQPtrOTqnlAfIeKaPYPpNI5uMaG
         rZ/2ra44h+ugwqTuebbfNm7+RY7D9TjCQod0kvXlFQyEz8HgzW5h1jLxgbMl2UvRp5At
         ei8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755521884; x=1756126684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lBuDQhj5+R192liT2+kUPdQ70rPXF7PgMoZ2/tcl2NA=;
        b=m1G64xvwCRzFN0cUQBXHjwexmqSDgG3OkULekYyyGcQWaJXZumXHe0D8a66bWtRVf2
         X9PP7GByfGmPusCLQ+bsR8D0SteV+TMQN7+lY2EQP9bV8IpLvKsUjH/cy1SYPuQss82H
         bB8oHSuRuD/mLi9Mac1ze5VsI2/crtlPZjdnK4HbMZNVXrXUBEfcGMF5zcXXnDWUoeep
         38R55fEET0CNvTMDFykKhMtRlfTnT6M7LLMM5oYM3kzE73d5x20jBp+691irPgJQf2ki
         JJrR5ihOTM6Ot/RaO92dI6xf7QevF8ZFX/vzuE/ON/5QD0FHpvxaot+FFmLf3kdEGG8x
         mW6A==
X-Forwarded-Encrypted: i=2; AJvYcCWx/9D7ml1szffXaJ5I7hdZNdbdxELd9LX3yordBAH+8LWd/ATlqdpOU46MKL4V0BAKNM4mdQ==@lfdr.de
X-Gm-Message-State: AOJu0YymiQsqLQ/tmVbGlvxrBPRH3AmyNrBIcAwfZDlz1g0cDBn1jR2e
	ZkWb9zocphGAeaj2avQpoISkO2zedWwmsD7lgAe/nAF9TvWjtTXLhNdB
X-Google-Smtp-Source: AGHT+IG82tZOHUb+VHFyTC5BGt0nlZXG+BHXvwbXWYbD0aziyC26dssJ0iJPPFNj+NNkzNzuMpxAwg==
X-Received: by 2002:a05:6e02:1c2e:b0:3e2:77d9:f8fc with SMTP id e9e14a558f8ab-3e57dafb37amr209874755ab.10.1755521884307;
        Mon, 18 Aug 2025 05:58:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7WEKNDNU1JaHxrbzPy2gnTOW8hu+LuPWWECN7kBLhJw==
Received: by 2002:a05:6e02:744:b0:3e5:45f5:e440 with SMTP id
 e9e14a558f8ab-3e56fbaf9cfls15207905ab.2.-pod-prod-00-us; Mon, 18 Aug 2025
 05:58:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbGnCOdvT6dDm13YFbRDvqcNswfaxOFqi9viDukHKguCBcA6RZOE7Ln8XHrv+bSSNGGOOwXqTyFSE=@googlegroups.com
X-Received: by 2002:a92:dc05:0:b0:3e3:b3d0:26cf with SMTP id e9e14a558f8ab-3e5718e985cmr281310985ab.10.1755521883170;
        Mon, 18 Aug 2025 05:58:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755521883; cv=none;
        d=google.com; s=arc-20240605;
        b=YTEZK4u/7NQSBetcL5QGS03P5w1vr2VM0+GG19YxJy0EyMxFwg7iTM97Yr0wiiNCvo
         R6uirb1DAdhPAL05rV5QLiPvXYXJ0EVKgejsYUgcTXKesVV+elnf1uTvNbYe91p/9RjT
         1Yx5dT1W3C0Bs+mixewFEHasJoOiuILpw6DfDodgMSP18pmAHgyD5MfzxN6ZFtZCXqDw
         T6BjItMMk0vNcCaCHIUIOWQB83vmw7cC54SKlwBsrsl7f1NGMwK2AlLDyg5yCHKtOxSD
         6l2LLNFRg7w7J8bkHJRiqobMDlk8GZ+A27q06zrYTOZ2JsVE6Vz/dJpvYgIv5+zHRqrR
         y8fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QyzL3GSkiAQfeG6g6YvIMRozhZr0+dfb72trcSazY0Y=;
        fh=aFsEHq5Bwk8fQf4+Hq/5+1sRqrwsOUPHAu+Sj9CHb9A=;
        b=I2dC6X0O2BtDlBO5EW36KGht92EgAYe8v2tTf5PH3J16byeBH6RcRiIY75/M2t0xN8
         jMwezAB5/W+QNlBQItNB1O9iLoNwCxVtx3gNJTtisKMHzuhnmEgrvO98Yv7KpDD3/z4E
         lEWQ22bzndjggejvnq6OB/nY5S3UygEY/phplf/ryQ1ez24hSIxzHwK5H841iFvcDXBq
         /jEmPBrxk/2DuUvEI5fJogQGfoMIzf0C2gL56Widnv1Uq6FROv4uPuc2jk7x+yURaL5I
         roTTCXtpPQPFBBBkGFqqGELVbwYJIzZ4tJfisl5C6wBUq2x3GX89rUgihFRUL6LIcv/w
         4MWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gcy8JlzU;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50c94908c5bsi373612173.2.2025.08.18.05.58.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 05:58:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-621-g_mIRCGpMROsggNnLgJ-Wg-1; Mon,
 18 Aug 2025 08:57:59 -0400
X-MC-Unique: g_mIRCGpMROsggNnLgJ-Wg-1
X-Mimecast-MFC-AGG-ID: g_mIRCGpMROsggNnLgJ-Wg_1755521876
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E3B3018002C2;
	Mon, 18 Aug 2025 12:57:50 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.44.34.24])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with SMTP id 4136D1955F24;
	Mon, 18 Aug 2025 12:57:43 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Mon, 18 Aug 2025 14:56:33 +0200 (CEST)
Date: Mon, 18 Aug 2025 14:56:26 +0200
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
	willy@infradead.org
Subject: Re: [syzbot] [fs?] [mm?] INFO: task hung in v9fs_file_fsync
Message-ID: <20250818125625.GC18626@redhat.com>
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
 header.i=@redhat.com header.s=mimecast20190719 header.b=gcy8JlzU;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818125625.GC18626%40redhat.com.
