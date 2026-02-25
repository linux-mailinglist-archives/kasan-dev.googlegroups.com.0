Return-Path: <kasan-dev+bncBCKPFB7SXUERBXO77LGAMGQECLCJQEQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id cBrWOt+vnmmRWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBXO77LGAMGQECLCJQEQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:31 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AEC8194090
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:31 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-504888a2a1dsf555766301cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:16:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007390; cv=pass;
        d=google.com; s=arc-20240605;
        b=GZVg8jwsjU9tB3XpMKWKHV0e7ooWeZ7s6X3p+HJqyD0L+SteFkwTJIzIuSoZh9Z68Q
         hBIkDQxIJktQ08oZyepQkRyLjvpfSJbmS1autmHhX038yeX7tW627JCvrgC0wvU2gfVg
         rywhoeclwOkk5cwhhDXSsGibk2OVZpkXlsNRA5f5M7Aj2SWdYK45W/6fqrx5MecNvV0r
         4kTMmeXERrdAGOuBRPCxXERLSv3KwpL26dNo8JQv69EU6I7ifsdFvVgDv4/LshWxdBWh
         7Masjz1/+oxQ9MfZOYerCjc8GxN+m5VMDrCDZ0BD83uIJd/zGIDVUiedJZSD3PmtMLjH
         oDww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=hiSHTNwZahUCi4cBHyIs5kIC43+TSzHgq7ybaV4ojow=;
        fh=iMGz3J7OxnmjtXDDiA9j2b39AStAgj8nlElgC//lTa8=;
        b=DMYkMAtPLpbOlyeV4ZIYBeBs8Qyl3rld3WrISgViCQE1jjnKsj9M+m+/7hoYLXxOLE
         je/UKNnFkd0lGHta015mrQ8ywbPZ18aTCGgFfhSLZX36fKNSHGigdxnayTusSIsxI0fv
         tvw0uKByee98NXSfsRW+5uGPRHMifLSz591dCxyfyvTbNYqa4Idk+hScY/VNdvDbMH/X
         FUTQWlxEHhpSZrQmKY3NEknkYlJwZ0s60dl0vY3AkoWY6MoombrOFXjZ/yl3kftdMR/v
         mUL8lZg8OuBY8W8JK4StU6k0ZMPQbXani/TGxw83WImiRkMddanYWxWB5F89U4wheCPS
         0sFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KlL766V4;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007390; x=1772612190; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hiSHTNwZahUCi4cBHyIs5kIC43+TSzHgq7ybaV4ojow=;
        b=HOaUch1GDuad/kirTda9HDAFS7PZ2jINx+rU26Z9MvZuqjOQWMxx/m8JtSHYJ28ir+
         PwZkNnQdZz4qdiyd7ox12y+NCsjt0CaN5N4ovwsk9u2BBLxwsrdTr+S1ncLD40gmWfqa
         aPC2zZuA124TnEPKpuQUBAqbFHJUXU96ox1n/yfddeKkst1MIKM7Q51r4GwLduPRUclg
         a5v5Ndm+cmxN0i3MwxxU2rKzb5Sq/S4jCKL3FtWe0xYzVlM8m93sbhwvYJJWOOR5oRcK
         3T9DSnNWYH2q0HM+q2IV4Ccb9+BxgUIjVNCP0/Mrr8ny5YrEqK3wTXXjGnc5Gk2N4o3r
         5Vow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007390; x=1772612190;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hiSHTNwZahUCi4cBHyIs5kIC43+TSzHgq7ybaV4ojow=;
        b=DewcjrVuVMFDqYotUmczg1lYjDuGiiwRmhqdkUvJJd7I9XI5Y5teDytUCYYY92e9zo
         0QtB/rtMbjl7ZjMEzKi1t77pdkY9PXyKJpiFKAqg3xJTp07EKQ5ldLqNqacMtIpo3ra5
         mhVqylIY87hDfO5A8QzR0Iflxkpoey2PDo8FRgmspIDlsQFPA/IVSV4cDfLf4fehQa42
         /mraEIOGtbsaCsa82ySamUWk5U4pWurJCf9XhZoMSyPYAIWNVsCKpBHeSQSGBEAB6Y2J
         45RIUua1NorLxMxRRNhde76FeSopFk7mhsX4Q3svXjBimjqjlpyaEn5vOw3MAkSwkpOK
         DYVA==
X-Forwarded-Encrypted: i=2; AJvYcCXQRy89JIOxH/6+VVmXUfj5KqUojS3KBNyhfS2HH2kK09twBN5RCsBIbN2GNpNSOvPk8mxyuQ==@lfdr.de
X-Gm-Message-State: AOJu0YxvRCfF3R0VS7xSdo0einWG9iovfHHtZ5Rr5T94iL2t2AyXO4VC
	sSvWf1FHOJaMqt15+eEsHH1GSf2ihTgQr/ew7lYDGiyLuhEetkaOsatw
X-Received: by 2002:a05:622a:3d2:b0:506:a1a8:c6fb with SMTP id d75a77b69052e-5070bba6b7cmr200646161cf.2.1772007389948;
        Wed, 25 Feb 2026 00:16:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GKh8tIR7nML5tY+jxunzMNMApNFetObZeqrqGlAG+hug=="
Received: by 2002:a05:622a:5d4:b0:4ee:1544:bc7e with SMTP id
 d75a77b69052e-5073bc3d618ls6145711cf.1.-pod-prod-07-us; Wed, 25 Feb 2026
 00:16:29 -0800 (PST)
X-Received: by 2002:a05:622a:302:b0:4ec:a568:7b1c with SMTP id d75a77b69052e-5070bbe6ab4mr211839481cf.21.1772007389043;
        Wed, 25 Feb 2026 00:16:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007389; cv=none;
        d=google.com; s=arc-20240605;
        b=S9w3sE/8rClblXbx1QdANIRFaOW+yKwryndl4xqjjd371lrH+YUW36XNBKgXEJDdA2
         Uz6l0w8JyPsrtMjHi2dwjtvLMZIK4zhswB1xzzPGvCkChBYc8kPRThCik9aXGbtoptC0
         vnM7iPrDTK7g9FMtVPb3D6SXjCiHoQNNn+mfz94bfz6iKYjuFZvmcid8umfBTzdGAGkm
         u3fgL8OLd/kbovAeVeTTnmh8PMHIoHztpt0Y8JBXkNEhURu7alKTsydzdqVsG8z2KVmu
         DxFOQ2igspkFX7Qjy8nAj4WpTGO7OtdCWz3LdIgxEBmm9jKiJSGdX/NihjDhujdXRJIS
         K/tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dmXeuzqCGEXbsFr6BMS6DZRu4kl8OFDlvdktSaTFzJk=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=io/o6YHiPRyvF42CCHQNqP/TnoHDldo9th+PjFhEoVPvcSuUl2W2T0JKB5UMUHpH1X
         rUyEJ3xg9ZzQWCo9c+kZ1utEuNTPie/Z47x5tqF2OtBM1XbmHzIZCocehq3fGQHoAdnS
         6/Z53ujMI0ATvAVIZQvwFvT+ExUmRYUrGgf7ONDi6u7X0yWZpPJ8IvDrPHRa74CLRWoy
         GOvbc75OgZmzZeGGyh6PvcIQQgNNU8Ppf7BRouDe45BI/rXPaKc8+Cj0NzfOnRYq+HY5
         9+zpW0gq9N2T/6Tc7xOdcYcuY6g+uRBR6sSFocX07E1IJ9sA1MIecgsGX2IV3RF56fsa
         +r0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KlL766V4;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-5070d53f115si4619921cf.2.2026.02.25.00.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:16:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-74-YXdFjCA1Mnetuo5LYiwicw-1; Wed,
 25 Feb 2026 03:16:22 -0500
X-MC-Unique: YXdFjCA1Mnetuo5LYiwicw-1
X-Mimecast-MFC-AGG-ID: YXdFjCA1Mnetuo5LYiwicw_1772007380
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 7F2CF1800282;
	Wed, 25 Feb 2026 08:16:20 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 37D111800465;
	Wed, 25 Feb 2026 08:16:09 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	linux-kernel@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	x86@kernel.org,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	linux-s390@vger.kernel.org,
	hca@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v5 10/15] arch/riscv: don't initialize kasan if it's disabled
Date: Wed, 25 Feb 2026 16:14:07 +0800
Message-ID: <20260225081412.76502-11-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: CycYgCPBDM-RSTnnq7boA9Kwv4NdYrKWuq7sEbd2Q1A_1772007380
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=KlL766V4;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBXO77LGAMGQECLCJQEQ];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.980];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,infradead.org:email]
X-Rspamd-Queue-Id: 8AEC8194090
X-Rspamd-Action: no action

Here, kasan is disabled if specified 'kasan=off' in kernel cmdline.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-riscv@lists.infradead.org
---
 arch/riscv/mm/kasan_init.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index c4a2a9e5586e..dc7cc0dcc7eb 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -485,6 +485,10 @@ void __init kasan_init(void)
 	phys_addr_t p_start, p_end;
 	u64 i;
 
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
+
 	create_tmp_mapping();
 	csr_write(CSR_SATP, PFN_DOWN(__pa(tmp_pg_dir)) | satp_mode);
 
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-11-bhe%40redhat.com.
