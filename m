Return-Path: <kasan-dev+bncBD66N3MZ6ALRBRWESLCQMGQEUIB3JOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D3E0B2C92B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 18:11:52 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cce8bd57esf10127342fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 09:11:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755619911; cv=pass;
        d=google.com; s=arc-20240605;
        b=iiFvKCLNj3o1zHi/dGrZG8zNwm+oxGtf8ARPRtaTtnoBlL/AMsQTMK0EtUgxu19rua
         oLxUCxn0qGHtAk56MuTFhGZg6Ot6rknS1MO3bXOWuY4sUpvSVVyMRiusdk8l6f45JkUR
         auAC7Is1te3f+v7MeqoElh0+pKBfw+dosPkJjdIPuqsxYkCZKiF1dGTP/AJjVEJof0w8
         QM21OFHkmPlxa3Z83ZYmLi0yPzLhM4Qn5T8kNyj5TfYnlzYcy0JXoOuCS8aFXJWWiSLI
         WSUvJjYF4XLIyYUygIGUZfnpIEr76wNiirvUyJo8qpARBUngd39X+nPJP3vh2MPgLZk3
         XtLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LFgkTSLTgoq3ibht9CeHtmCAMjiUq4+ZNFB83EQJbQA=;
        fh=DwFCtjAcR55z4gtCxcDrBdZrvocyxXUfaPwWxMt5T2I=;
        b=SEHgWyQ2M8uT7ydR1i3uHsB6ojiFyEk1OdOPp1Jt+04f1/DhQruOtiOg6mGIdoCtSk
         xt1AytGikzbC/ie3jHa7RyaYBOTV0w7nssUzWPmqL6G5rWhX/q5piWgHia3MafYUaloV
         WnUiniGfvRaltb9dcjr4a6qChK7MwwBP3yzIrrwwvyQvLe0bmzM1v1dCXLd1I+zsbGZI
         cJgp4o9T7/2TEhnXB6f3JucYZUZG0qGe9ZRtgFP9HQHa/NtZDXWg1f98n+ObOUn0U5hU
         vkWHsFxwBKFo1lPZUYIrfKZ8Uo4qlZIwsMqUcmpbzcxo81W2KbWx3lzp/B2diZYhZQ7g
         vn5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cVtR1lwR;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755619911; x=1756224711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=LFgkTSLTgoq3ibht9CeHtmCAMjiUq4+ZNFB83EQJbQA=;
        b=ZvsTKPSfpY6lOfgCdIerciNIjHX/LrWt7m8PezLLkeBQGEuGMsu55uRAhgF8jeJQ6R
         gSt1trRl/g0cEMKsNXIdvSuQlzQZfW0JfpqP7REUhYzMts5JPleyNM0uTJpEyr/ow3kc
         EeQ7ieh6eX9YcKd9hhnJOF3h5M7qGbhTovBhpKFSRmYc3mS5IgrSIkk9rXvP9V+TdIgw
         yt7i/e0P4E2KqR0d/gOdVoC4WvUZS94VwIzQ8Ml8/lTzfAI847wQXNx/pCXxwZTUR0YK
         1TrYf18iN+XdBXeo03lLPY1vEwPYojj3ajioxwAXy6BL/Z9hX1roakRQUAVD4JysfYfR
         hlig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755619911; x=1756224711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LFgkTSLTgoq3ibht9CeHtmCAMjiUq4+ZNFB83EQJbQA=;
        b=Wlr69bYt3VOB64QojiHpyJepk04yOuxgQJGvAKlnm/RJtGCtObKxffsQ93BBusKw3z
         kviSqj1IfDV3oY0ZI2fcY/4S+FCRDSRAUSMTz3J00BVEiiVY3JgGlE0RlLWdLyPBE4yr
         5V3BYgZj6Lu79GNk7NM75its/okTmgXdPFw0gJLcSKhJCMvNDPkgqw48RwThClliklT6
         2FL9zntovXCQ9tbqhfKPjppHtv+xZLS+/U+oFZZa8UFREbUc/i0CtsS2k/amhIplcfDg
         dloOR80+zkAwYP8RHgCxaxhxuOgY/XmvuFAQE47zMm8fpvK2fKaeF8el+Q/67Te+9QWB
         N0GA==
X-Forwarded-Encrypted: i=2; AJvYcCXetW1Xn9rIjDo6IKjvqGN0qhH0k+HHM2oo88wVzwpUbhV8FiB62S4oiaZim6/66L/Z2wQDzw==@lfdr.de
X-Gm-Message-State: AOJu0YzBQ936+YIq+v7zZoGwQo0ZXtNFwmeW8uGSWo7+7IXiwjIsxcEl
	b/zOMcpp0Sj/6xRy2mpu5K+fF/8DG+DO0tE666tKD9NWK8tvM5ZVkQui
X-Google-Smtp-Source: AGHT+IGOB/plmP6R8FBK9EvdQRZ37fMZlFsn3DdFwmlt1qcjzI9GobydRrLi0ovMhtcEDs/nfoYBmA==
X-Received: by 2002:a05:6870:7009:b0:2d6:2a1b:320f with SMTP id 586e51a60fabf-3110c1f4d2fmr1977599fac.11.1755619910542;
        Tue, 19 Aug 2025 09:11:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZefhRbjkMzm8O63fSOIRxc6sKfaz0KeiZl1wXtv/u8R0A==
Received: by 2002:a05:6870:8999:b0:2eb:b30a:f5e0 with SMTP id
 586e51a60fabf-30cce51e424ls2954225fac.1.-pod-prod-03-us; Tue, 19 Aug 2025
 09:11:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUBY+OfmnHEu+kNEVTJAWJjnqK0H0B3i5wOnn6eRg2EaPqj1PtDJCs0Cd/3t7UcMjEwY8gnybijHmM=@googlegroups.com
X-Received: by 2002:a05:6870:2d3:b0:2d6:49df:a649 with SMTP id 586e51a60fabf-3110c442a03mr2374324fac.31.1755619909248;
        Tue, 19 Aug 2025 09:11:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755619909; cv=none;
        d=google.com; s=arc-20240605;
        b=BskxvvVck5Ia2m42B5Q0ZerIUNRnntktATuRT0JDyDSXcUWDBQAcz21DnBtW1v6jmh
         h4lJOwWfrngBiI/JIaLbP5RRyMF/ztDY4bRLtvuKll/AdLCdMk26J4ozTonAtf7D1AbN
         6d02Sxnd18rI9IILIyO8Ak0MrW6+vTD50ZX9K0gGL8noIC6toBD8F2EowXgZu+vXOjQD
         MTjzPVXqbpLIa2gT9ztRWHHMUE1J8LWSmcNfRvpxPeeARCifa58qmOlX5bWJoQrB5oW6
         7VfaHa7uL8w+soNYOTWgtrTp5pfhojL71zKh9N+A0ZVuL1+e8C0N9hU5/Nfo9BU28FDp
         RBhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=f/3a3Z3L0HEIC3vaPkLm4MfWk/+SLSX3X+v7+5Ljf+M=;
        fh=Ika0asQmnt9ZKT9SvDFiWiNvgpsnzsdMaH2/NGTFMts=;
        b=CQF3Ujs3MKiUMqCZPDMw6jJsrK3XzB1rcq6dGy1/Q4Axo8WhOc1AuHjOiKIGM0gXJB
         yD5JNYhZ8/FbvLV5lKsllqfNZB5CQ3eDihYLtKfgag8lXwBtUuYRGqvgA1RZNyhs592D
         ZZYT2oeNDYmMV3vv7LldFhEnpekMKEbTHVNgufyAHfU/Tn7iTTELCY3BnfKm74t5Klb7
         mkhPKTDCjlh608XKsz9iC5aGYvx7JQS6EOhxMiMKYxioLbam035Y/vJmvfrUxMwUtZim
         rKWr8K3eOKpCUr8MyjQ0ZN9EISjyQSgazt/dijhZFOPfz8vaAyA7F/Di9nwjszSzYGe/
         jWQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cVtR1lwR;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-310ab91bba3si565073fac.2.2025.08.19.09.11.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 09:11:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-433-tSTadv3EM7ahhzm854JzNA-1; Tue,
 19 Aug 2025 12:11:44 -0400
X-MC-Unique: tSTadv3EM7ahhzm854JzNA-1
X-Mimecast-MFC-AGG-ID: tSTadv3EM7ahhzm854JzNA_1755619902
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id B112C19775B0;
	Tue, 19 Aug 2025 16:11:40 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.225.95])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with SMTP id D73F5180047F;
	Tue, 19 Aug 2025 16:11:33 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Tue, 19 Aug 2025 18:10:22 +0200 (CEST)
Date: Tue, 19 Aug 2025 18:10:13 +0200
From: "'Oleg Nesterov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dominique Martinet <asmadeus@codewreck.org>,
	K Prateek Nayak <kprateek.nayak@amd.com>,
	syzbot <syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com>
Cc: akpm@linux-foundation.org, brauner@kernel.org, dvyukov@google.com,
	elver@google.com, glider@google.com, jack@suse.cz,
	kasan-dev@googlegroups.com, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk,
	willy@infradead.org, v9fs@lists.linux.dev,
	David Howells <dhowells@redhat.com>
Subject: [PATCH] 9p/trans_fd: p9_fd_request: kick rx thread if EPOLLIN
Message-ID: <20250819161013.GB11345@redhat.com>
References: <68a2de8f.050a0220.e29e5.0097.GAE@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <68a2de8f.050a0220.e29e5.0097.GAE@google.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=cVtR1lwR;
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

p9_read_work() doesn't set Rworksched and doesn't do schedule_work(m->rq)
if list_empty(&m->req_list).

However, if the pipe is full, we need to read more data and this used to
work prior to commit aaec5a95d59615 ("pipe_read: don't wake up the writer
if the pipe is still full").

p9_read_work() does p9_fd_read() -> ... -> anon_pipe_read() which (before
the commit above) triggered the unnecessary wakeup. This wakeup calls
p9_pollwake() which kicks p9_poll_workfn() -> p9_poll_mux(), p9_poll_mux()
will notice EPOLLIN and schedule_work(&m->rq).

This no longer happens after the optimization above, change p9_fd_request()
to use p9_poll_mux() instead of only checking for EPOLLOUT.

Reported-by: syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com
Tested-by: syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/68a2de8f.050a0220.e29e5.0097.GAE@google.com/
Link: https://lore.kernel.org/all/67dedd2f.050a0220.31a16b.003f.GAE@google.com/
Co-developed-by: K Prateek Nayak <kprateek.nayak@amd.com>
Signed-off-by: K Prateek Nayak <kprateek.nayak@amd.com>
Signed-off-by: Oleg Nesterov <oleg@redhat.com>
---
 net/9p/trans_fd.c | 9 +--------
 1 file changed, 1 insertion(+), 8 deletions(-)

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
2.25.1.362.g51ebf55


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250819161013.GB11345%40redhat.com.
