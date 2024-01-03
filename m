Return-Path: <kasan-dev+bncBCO3JTUR7UBRB5WG2SWAMGQEEKFFSDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C7098229E6
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 10:05:59 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-556a28dfb41sf518456a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 01:05:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704272759; cv=pass;
        d=google.com; s=arc-20160816;
        b=ll5DZwxBKeTsuaingdQAsXWwWXmPfy/gRSE4EtSU+YMf3+ef/yyrA2yjol4Dy53Mus
         yHPXHJOJePt6bcrMlXKaxodfKqpfkfooS4QmUvqwY3ZUmBN7J9QPItqWm5PYq6PhSbBI
         iVaExC4bPmeqTZfq459qXN6jIFXkvD7nN7/7MXBIBnzRaQi6vyY4kPD4PenUvEUNyjxt
         hQXETptX9z7MuxMKkjErQfcIcN7phCKJvw/WbBGUUypNcSyq5EM5tWCTzKBYg3SJDGno
         X+8V/kMj1MQ9gwATwu6qWFLe2UCCLGTEqrQPcv3j4kk8BSc2+kyu6x3UEpc/KK0tD1Gy
         5lLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kv8dtLg9RL54myH0eX7tlI09SB6I21EjZ2y1QX7ItbQ=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=iHkIgRaKldU0YQACKaWfhTWgYnHi4zXiZKWPZkrIpb+0SJiDHIqQj+OnYBoy6oxmX9
         vABCACsQg5fxfu/bpSPRuWFXt7o9u+Hxt2FdpzYGLbHTkOymCc9DuRDV3zFizbxHqx5S
         +GHgUiCNk1bEe13R56CK9BLF+XJv4aZng5XHGfhPRyja1YsvHuCluumKb+xZ690RkA1B
         pXd4q5BgafkcDl8WR1VqA0caPfHqABzC7zESu+6DyKEhjbZO6OadyWX4IZiqvvCcDgj4
         xCxxjSm1lTmGWUUNeJBqDH0VMfApEQ4cnVXvSutEMMohGJL4VutYAmhB8QoQm0mH3OU+
         j+Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=OXxrEElr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=eiUS5Rvv;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=OXxrEElr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704272759; x=1704877559; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kv8dtLg9RL54myH0eX7tlI09SB6I21EjZ2y1QX7ItbQ=;
        b=xniEecU2eq0UM/edMVyjWf7FfES5z+kinb0F05zu2ndQ+vK63p5e0OHX+JtcZgrQMm
         XFMaWo9mbVHKwdDRDy8nQuMwg4iKTOfIWlU5ulU3+9dbtXkxsIQoiCCXPbs6Z6busN7H
         wpEcDd06eA2NEp6WOXb5k3ZFvBn3T1gBb6/bWggb/AEJD12JP9yFHFkwrAAhWtQgdbYN
         dJo9yCtlm3FGk/AYrRnW5/X+cd29jniJgjaO6DA+d8LOQMtBSqiRBENJpa9R062Zi0aT
         gF3EvX3wf3K+cBfMLsFx6FV+EymN6Tn53EhOs1sPBVSdS2FIJW+ntiO++Kb/j/hj31dM
         NjOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704272759; x=1704877559;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kv8dtLg9RL54myH0eX7tlI09SB6I21EjZ2y1QX7ItbQ=;
        b=Tp69jE0Wdquru2IZXi5PxRKEwMk6yV8yeVqj6WTEzv3VTlMh8zSHwLXIUwONIy9/AF
         9Iqb2fP4NB/CiK+M64ZPjlY3UwmeI+8etddYGrjErtHfbCwcubRQscfcrvOtnmQ8Vk8U
         Pv7wJ5otzhJ6bGPJUY26m9ugOUrtKzbVjug0/B7o2X9TZ5/cJ3JdH0nSn1VRN4BAd/e8
         T2Z0cYSyq+9l0DFkv++mZS68JMXXPwO3ptLGwo7RFLHRv/G9iHrmrC6DD4aVOnlX9Gfz
         cH87Ll5S+kesfG0qrNsnbbNR+SGUfD91FBezDflXNUMoKzMgutJMqzJH7gAj8MVzvQ5B
         1KAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyMDrb3gAB0e1GrSa4/rnF+57+svpeQnpWs2KTdmhRaBLi87LRk
	BGHQr9hwoXt8hehKPUgsPDVxjA==
X-Google-Smtp-Source: AGHT+IHAk4ur80NSYRLnhQRH7oO5A69LzMaIAEKi1SemNMORFi4JRjAl8uBzKxDPK6q4F6+MFOvRuw==
X-Received: by 2002:a50:ab13:0:b0:553:2b8:c9ff with SMTP id s19-20020a50ab13000000b0055302b8c9ffmr11869735edc.76.1704272758715;
        Wed, 03 Jan 2024 01:05:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:50d0:b0:553:2a33:7d33 with SMTP id
 h16-20020a05640250d000b005532a337d33ls1020700edb.0.-pod-prod-01-eu; Wed, 03
 Jan 2024 01:05:57 -0800 (PST)
X-Received: by 2002:a50:d702:0:b0:553:354b:18f7 with SMTP id t2-20020a50d702000000b00553354b18f7mr10450791edi.33.1704272756766;
        Wed, 03 Jan 2024 01:05:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704272756; cv=none;
        d=google.com; s=arc-20160816;
        b=U7n3tfgGFaS4oxM8aYWDQp3wTGFza2nPXi6z3whBrRTf+sehqrYktBpJyXsmDfXxzR
         EuI6FUl6/qRs2EN/M/gVHWlKd443bg+cj+22qVxj/81spclPygoEaLt0h5rHxOLDOGvb
         FEv86nUuSkp3mM9BFwW6HEV/pOHWw0Tv1v7C6VeY7IeYQ6SlEaqSJOcE1CL9nAL1zehe
         xrlLEIXovnwQdQm2FVE3ix3AlD4jg3Zkd5hCzb8af9ro5PcRH+76mHq8D9dWGuj/SzpY
         b0Ct/EoPqjVLy+Jfypo5LNd7BorbmWqQfbgtAyPyLGFaMCQSSlq7+b+dhgNLVZ/KBpy7
         fsUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=9YHgEMpLm7folf5G8Ij+ZasKgK+9OLJsmoPBAUvLJ/8=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=QkPkDobnEOcZaMzdnQHs0Rp3P3hkseGvvDquXrInfCue16+kbwU5J1SIVXGzCA9hnw
         5NbpH4mcXlvTnW2cy08BZa1sVxVJ2zUFung84lq83cpgTCt8MwE2OaZCcJVIhKZhZwtP
         kPBqmJH39MRWB4Ih6MvI6EYWtOW45MdvAR9PdIXAvCd1sanBBjVE+E9wUlQoQt7jJOkD
         d1TcTLSOZPaNFgEZ9Sw8Y2yHBCfaH8G6D2/domsFOGmbAwgNVb4SjTQPuHve7L+GvD/o
         QZYEM4NiJH7fM2/pWWNGm3z5KrgzXXIMtrDozVQ31SUZE2qkYuilVDASb6D0O+aVv1bv
         vPhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=OXxrEElr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=eiUS5Rvv;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=OXxrEElr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a6-20020a05640213c600b0055593fdead7si303483edx.5.2024.01.03.01.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 01:05:56 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0712821C64;
	Wed,  3 Jan 2024 09:05:56 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3C2421340C;
	Wed,  3 Jan 2024 09:05:55 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 2UebC3MjlWUEaQAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 09:05:55 +0000
Date: Wed, 3 Jan 2024 10:06:46 +0100
From: Oscar Salvador <osalvador@suse.de>
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 10/22] lib/stackdepot: store next pool pointer in
 new_pool
Message-ID: <ZZUjptpWL8qBO5f3@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <448bc18296c16bef95cb3167697be6583dcc8ce3.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <448bc18296c16bef95cb3167697be6583dcc8ce3.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Spam-Level: 
X-Spam-Score: -3.71
X-Spamd-Result: default: False [-3.71 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.de:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 BAYES_HAM(-2.41)[97.30%]
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=OXxrEElr;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=eiUS5Rvv;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=OXxrEElr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates
 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Mon, Nov 20, 2023 at 06:47:08PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Instead of using the last pointer in stack_pools for storing the pointer
> to a new pool (which does not yet store any stack records), use a new
> new_pool variable.
> 
> This a purely code readability change: it seems more logical to store
> the pointer to a pool with a special meaning in a dedicated variable.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Oscar Salvador <osalvador@suse.de>

 

-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUjptpWL8qBO5f3%40localhost.localdomain.
