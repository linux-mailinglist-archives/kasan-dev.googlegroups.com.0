Return-Path: <kasan-dev+bncBD66N3MZ6ALRBYFERTCQMGQERB275XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 14A7BB2A0B1
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 13:45:39 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-7438200a0f8sf6491280a34.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 04:45:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755517536; cv=pass;
        d=google.com; s=arc-20240605;
        b=eYyuqDrkW8LT7unYKPCbNcOV8ERHXJwgC02pKFtmIoW1EavRfj2RsUdB6V77qvl75G
         3kR6NkAaP+sBm+W9+vIosIBX1zfwHJZiTMMsBphbrbHMukpRnyvgSPkHnrYLYb/gpsOB
         KBrm2uTRCEGouBPJziZfrTS146vifLrmgAju6melwe+qmxDERuRrDOlnY7m8xEOsscsB
         Qb/W5Y1DJ2Ect54AZT4DSod3jQ+vzlHmVeqx5C+7why3QDsmU7p8kxFcNevnjmpO1xNw
         ld+RmdQavGfTsygMjZuqL2ND/R2X7ADTLL0BHPgU3jzXGN5dABjOsRUa6rp55cZS1pfv
         RjIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=XuJYtPk3QCeCB0kZbcxNERXFCD/vqHZvQk9MqZR/54c=;
        fh=V0WDrblXmzR9miRkH/pJNrQ1coS9kgQv4RwYBwx7CZ0=;
        b=PfPd2iUGZUuHqoJBT5ncAA8ZlymXy8n09NwKR3CIcwA9kFFeJ7OdAoGg3pPY/aAFj4
         Ka146ReS0gG7bgzcJB8O7JW+Tl83J53aLnH1x3EUWYYT/4wnrxCei+WUyHW94ByQCt8a
         xeayuAVA2gyxBSLmC69NfVvSf4m+HOLbf1OaTM+Y7zX8SfHk7mWtqwj0Lu4HfvHXjjKU
         YtX199ajncxRwVxtb0YA7+iUJiAGRVGfYr+MyqRxjOXJsrd5KnbHTWBmR3IpWTEGtCb/
         +NdTPF2ZPSheeKDIIMLhGCkuC63+Jc33X+Op9RDI3ez+2ip5Ls5uzfHkwGawdGCOrn/7
         /I8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Clt/vjFH";
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755517536; x=1756122336; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=XuJYtPk3QCeCB0kZbcxNERXFCD/vqHZvQk9MqZR/54c=;
        b=dRdZVooBLFDkr5YcKOSWSj0NTFzHGcPz1sRTWnH7U2oZSoFca+uhMC+5I5XilHXt3i
         3ZD69LalKf5nmWcCoHb6B2kuqYLxUxvyPvbDmQuaJ4lDPSx9Hvg6TTQCFPrzAR+kmHHK
         SKQrBsSSdD17sEN+laOfe4p2tGGRBQ474/5qd1W7DQI2Gwzf29OD9ebr1iSM6IBan451
         1G0fzws6wTL1xhOZNlQZWzO4hXqttkGTCKVWBLlIb9ywRN9uuTtLM/5YByeQYFqa473W
         1UPuzb8zqDoS1FhkXfr9duJdeYB0TSlS0wrLQ0UdvCfLN8lboNsyB+UE8/PoBzgX3GFK
         UlgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755517536; x=1756122336;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XuJYtPk3QCeCB0kZbcxNERXFCD/vqHZvQk9MqZR/54c=;
        b=SkYaYXQ2PmhxUkdZ0x1RdnEK6GaaztxPTa5Y/4cXRVMVe5jVe98470fYgcOy/tqsMa
         29lsDlYw/fy9o1dSRafek87XORKMsisis677JlzS+3dK98VjOtpN17TIq4rgnQNru9XH
         QZsziyVcifDtfooHgv0jVEVeZeQO7uY9jASgVd95vBUdP8B7pPwIY5ml0IABIMrcqCPT
         vqmqfEFUDuvSmAMfSBrmYBXGSTRa9VZMdFZlPZuQSCd72JrnVYy3aqrpw24IBnAsNhXl
         VErVa2ffd8gLuqqZFT3l/5KdypRUV6dLlhGcToFLQWmcStETkZnTYS0UfsI7R+T31K1I
         53cw==
X-Forwarded-Encrypted: i=2; AJvYcCUWnf48DL10280wK8gQKCF36AoPg0TSrC46ib4TFZDFHMwFx/L27DAO7JAsN6nCVUioHhwGlw==@lfdr.de
X-Gm-Message-State: AOJu0YxKwaeWORLAyrYw2ZW0M0tFT1nz4agx/9pxS+kpTTn1oIahBcg9
	xSI6UCwE1vJK4+5AjZhlhJihrITPfdjWBjlZ3bbJWo063+d7++zG5vZh
X-Google-Smtp-Source: AGHT+IHv3M6890tNQYIYMLWs0Y3k2eT+leMAOfggbWfLcJoJi8xUo8j78iNjQ+K5mEQVN2t/6NmxRQ==
X-Received: by 2002:a05:6830:4391:b0:741:5d01:361c with SMTP id 46e09a7af769-7439ba59fbbmr4805162a34.11.1755517536308;
        Mon, 18 Aug 2025 04:45:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcnYXRGJ19ljHpnoTTJA81qlcolSc4ttyek95eo+3FqOg==
Received: by 2002:a05:6870:d152:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-30cceb68b39ls2546739fac.1.-pod-prod-05-us; Mon, 18 Aug 2025
 04:45:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTcfgpeWYFonA/g0v5nf190yXwD80HeWlB3hCvq+joAdL0MOaW4kju8Mh2r4qQym2LHEh+JbC7ZAM=@googlegroups.com
X-Received: by 2002:a05:6871:b27:b0:2e8:797b:bf23 with SMTP id 586e51a60fabf-310be646446mr4604122fac.21.1755517535420;
        Mon, 18 Aug 2025 04:45:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755517535; cv=none;
        d=google.com; s=arc-20240605;
        b=RtcthblL96GWdjAPznU0eRunXwyB1wowceeDmjDorQhtlsC5Of4mFot41xIKhzZjZZ
         eik8UgFq+dytQ4jhhG6VYONhlJ/T2R4OfitvVo02ee4hTpwt7TO9fL9gyPeQ2MPAem8b
         XNs64B0NwPU4DtIkWZkA9K9jR9h+tt0Pe9+Tzvn7MFkxg8/ZpxdFeSV7LS7GAaQwFbX/
         iMqS24m2fJDxONyayOo886qXfWNiJC1hU4gzKqMK+K9X0+zcsGmaDpg9B2dV4HFl/Wmq
         6kZ7J+WmxCUZgAq8C7DuH6gQAROQaJW8NRqJJ7ySfGIbKUab233QN+QD7F3G4agAo1UW
         jPhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Fu4mWedunRpepQK4vPdF43r3Z2WEFaYWndiALSzs5Lw=;
        fh=9ajR4e7FBwwH2Cim0QP/aLz3/ba5tL96t4k/DzL5SYk=;
        b=ThHPsqRqso5QwlRJ0ZNq0Fv67XK7PSut/Iss7fcH3jJwVu0VOBjkZmK0t2eSR1RtST
         fDqjZOJiZgux8hVRTH6eICrHzCnxu9iJaqFsZEeVNqT+OoeOCHE5C2lJZbn0o311WSrj
         I8tRlQqGqZod42zqz+fBXZTnj32KUI7dSzWSeKbErqKECrnGMCRP+FZ7OaT267lDSScM
         V2WFRuhi0SwLpqa0C3+ebPdn5NDELesYmE/ZtcFYzZiOicmwyU7wViUk3TolvieFz+Ld
         GAVUcQ3JKHRlMKQwdALO1JAeoI0bOYlEeZzQDVXRfuYGnqcaQQFiZTe7/aTIoTaEfJVJ
         GjuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Clt/vjFH";
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-310abb4abadsi374280fac.4.2025.08.18.04.45.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 04:45:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-17-GUL-TeqQNc2gGJcAky-ovg-1; Mon,
 18 Aug 2025 07:45:31 -0400
X-MC-Unique: GUL-TeqQNc2gGJcAky-ovg-1
X-Mimecast-MFC-AGG-ID: GUL-TeqQNc2gGJcAky-ovg_1755517529
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 9ADC3180044F;
	Mon, 18 Aug 2025 11:45:28 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.44.34.24])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with SMTP id 48FE7180028E;
	Mon, 18 Aug 2025 11:45:22 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Mon, 18 Aug 2025 13:44:11 +0200 (CEST)
Date: Mon, 18 Aug 2025 13:44:05 +0200
From: "'Oleg Nesterov' via kasan-dev" <kasan-dev@googlegroups.com>
To: syzbot <syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com>
Cc: akpm@linux-foundation.org, brauner@kernel.org, dvyukov@google.com,
	elver@google.com, glider@google.com, jack@suse.cz,
	kasan-dev@googlegroups.com, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk,
	willy@infradead.org
Subject: Re: [syzbot] [fs?] [mm?] INFO: task hung in v9fs_file_fsync
Message-ID: <20250818114404.GA18626@redhat.com>
References: <68a2de8f.050a0220.e29e5.0097.GAE@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <68a2de8f.050a0220.e29e5.0097.GAE@google.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="Clt/vjFH";
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
> HEAD commit:    038d61fd6422 Linux 6.16

#syz test: upstream 038d61fd6422

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818114404.GA18626%40redhat.com.
