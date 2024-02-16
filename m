Return-Path: <kasan-dev+bncBD5LDHXSYUMRB3MUXWXAMGQEEYAOMUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E0288857BEE
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 12:43:42 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5119f6dca82sf1827177e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 03:43:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708083822; cv=pass;
        d=google.com; s=arc-20160816;
        b=DzsbPNI2P9ehEpu12Kjh95ZUlsIgkRvUdL+eIRUgT6qHlX1kL+zXNU8xLo6YbpnKbn
         GWcyavHOupxHUBFOyaZUDPwttJMJFyG/DBJ8Q2Qz/vj3ZH+yW7W7peZDP2EgEtinW44T
         EPAzX2AsIdH45YNhzmTYILrB+gmP19slkTXvOhHrhiYbccI9wv4ozjdjY0c922/BeDRB
         QEoyAkNvSmo9CkE/ngTc2JMptby5LnzTujowJOKp/PIyR/mdrUfSzvXI6oNFakKao1aT
         LWdfhhfzRz/ptl16FXtjrwxQhBD3+IJLDGithm5PofUlRSiBGFBtFKiSxUGSJo3BLBYD
         jEUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=L0PV69Bgw0ijSSx/AUOIigm+5rCwiFzDkCB1U1rlCkg=;
        fh=MAGq/DUaB2ahZFnUJd2hOIIS2LzIhuYMjqzVKNMyRMo=;
        b=tvhg/EtfotcteC18zAa2wxlTppd/Ub0/B/5OGWVMOJlpHCU401rpq5rxyttijDYu2g
         Ejh7cpoj0hu8ajYJNWD6pFS90APaKJiYhnWVC2c1wK9pnCN5eBFS9IZBw6x/5pqoQ8AT
         B8dOBV+IjQi2xDPBPApmfUsxx8ojRQ8cpxGqTLgtL8p58uopaHKzGMvR38bljmVSQZgI
         4pvJuxozDJLZTL8SjS4kXpVQF/d8yTrum9+MeHL2pZyc0OdnfxS3F9yw3WNSP9iGX2HE
         7QMwxOH9zkVR2yqG9bNcof9k2yvXOXAenEzdvgI0AXRkSwrREO2qlkr5Fqh3k689Y6UQ
         uU5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=OCbMbtZT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=e7U0D98d;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708083822; x=1708688622; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=L0PV69Bgw0ijSSx/AUOIigm+5rCwiFzDkCB1U1rlCkg=;
        b=uF88rP3TKcz2wVba07ZVZov2GTP0xP8hkRQXtUM+eNGBqFSTsMWAaTDbduWUpcnfje
         wv+UI9kY8l+V1O6uznyu0HNGthOi65jNiV3b1f+kwhdpYEckMm5o1i0SUbJFCvTC1cps
         jsSFQkHUU1QReH7SFxQC0opgUfW4jk426JCZJaHI40de6zCYawC2TLlEc6Y4kHPhq6ZV
         zVDTmAt2FuZzYihwSDswfFylcmL0hv5y6QJ7lVItXHs6+XhFfnuB1lfnslSO+ul0uhGX
         m2WfOs4o4Kawv22B0amB6vvXQIjXb/fYQcNpSpS/ZzzoN0Fi/WCOSnCvyozqSUG2f2bw
         4yNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708083822; x=1708688622;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=L0PV69Bgw0ijSSx/AUOIigm+5rCwiFzDkCB1U1rlCkg=;
        b=eR98ysf1H1Havmq3n62NVoDBDDY+7JWT+nkJYs92pQoHk6d1MIY4915zKLtaCuoQNd
         78A78JuEqkSDrru3cZ57U4XtKIj0aXRwD4b0GZ3ZgAp6HR2DKyMfGcRkfOuL5q2sUtXJ
         47fWZmu2jdwoRLgLEEt9CI8W0DRqHhlm5TB6ASmWcwKSDcV+eYiY3npqqo+KaRhpYVzM
         P0Ue0EyHiFPwvN71B4jAFFD4/8jQQEuBZ4YEoO2dE5x5FwVhMeGxd+ksEnstFIdEFJIS
         6CC1rvFWq2PophumZkVTlyPMk7FK29kXnMUsoMXoEMtp460H96qp4QQMnG+Lg81SJCZ3
         QSXw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1IwjxAwwQByBnMPhs+v9yN3nd3xbGIVB/e6l9c4vPs9PxvgdaIYtKoA7q7Voa03jEwoL7ImL3ivcI6w66NHLuUIpfltThAg==
X-Gm-Message-State: AOJu0Yw4Prq2s52FFzSutJ0+GTmuxr7f3wSUZZYSLxTkgxdr3sobGrRc
	ugeEK8iZNHrzfoqmH9HRgL0Dk4F3Sdpqw961nSE1VkgBK45hQd5M
X-Google-Smtp-Source: AGHT+IECPe7mf8dqS/Ovn6vBnKTZvCBUHkXAlTpxbTTexd4fKbuSl7SwFTobplJAKjtjUf8tD8eb3w==
X-Received: by 2002:a05:6512:488b:b0:511:86c0:dad2 with SMTP id eq11-20020a056512488b00b0051186c0dad2mr3281188lfb.62.1708083821763;
        Fri, 16 Feb 2024 03:43:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:108b:b0:511:7a78:7ea9 with SMTP id
 j11-20020a056512108b00b005117a787ea9ls118336lfg.2.-pod-prod-09-eu; Fri, 16
 Feb 2024 03:43:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV+ehh0y29LBrk20+DskyStD2SqMDyMOeNpvVYbyO7J7ZibVMSYMY9aYdHLt68bmWgWEZmEm45kn+QV+9QP+Aloxp5NI/QPQRhSpg==
X-Received: by 2002:a05:6512:314c:b0:512:8776:cc18 with SMTP id s12-20020a056512314c00b005128776cc18mr2982298lfi.25.1708083819574;
        Fri, 16 Feb 2024 03:43:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708083819; cv=none;
        d=google.com; s=arc-20160816;
        b=hS7/DmwYx1zxxmDrNz1Vd2623rMw9Q1lbQPBP0xDGYK6KQcnAM+/ZhryMJQEGDSLDQ
         kP0h0WIeDqWuc0fvwG/cuCdUouog4x2E+xwtDtwv5pbH+ymudt0pnCHRb1LcfAUWEkmK
         a0yzV0BEIK821lMNbCnHxo6ejyqa99bJyLy5mEsNMWz8qPoAHgyTfqmuqovmVSdHa0G9
         nCDItZHDwxYkb3yX/YkxVcI0/eRDf1psKS0RRk3N0kqSOyRBUkEjPqgc7pGwpT92PyS6
         4lG15I27wDXbDawPVz+M2+YcmgW6bEYMeX7il9OBREOrze5woBxym3zzkqX0jXKGiry9
         X/xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=icwAL7s9OAkuwREddOlMt/tnCHt0fYsLsyeQACPjgPk=;
        fh=qtx7ZF2675XcNwyzcRFtw/q+Re4vscy82Z1/xJCeqD4=;
        b=fuOG/odO48EfByjEMgIgyb6RrFCIwtpLxDmEBYb9Ei7WFm5kS75bb8XAdKzMj3YHxy
         VsHe67mbvy+YHAVkR7sfEggahWCItXSLLsYv/a73Ripu3FOJJPyIgYG8Ltj1kzuT2D4S
         9LtZ4uH1z1vWw3I/gh264GLcI7UDnc5n9++naw7pr6kKC8ojfvqEpVmELZDzz+Be7Awh
         BA4O8/kMwD4ml+k7OoKHLDxwWinqq7rnfZJouvkdANxA0agm/r2yABb+0LJetydRQSVR
         DCXYc1BPV2opmbVqT+Jy2ONVPCBc6aukfeZL+nSgrZVqel66KKZ3YQlzLcFD58tcveak
         MVkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=OCbMbtZT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=e7U0D98d;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id dm7-20020a05640222c700b005617c6b0e51si105077edb.4.2024.02.16.03.43.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 03:43:39 -0800 (PST)
Received-SPF: pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap2.dmz-prg2.suse.org (imap2.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:98])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 1903A1FB65;
	Fri, 16 Feb 2024 11:43:37 +0000 (UTC)
Received: from imap2.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap2.dmz-prg2.suse.org (Postfix) with ESMTPS id 09FBB13421;
	Fri, 16 Feb 2024 11:43:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap2.dmz-prg2.suse.org with ESMTPSA
	id /e5rAmlKz2U2FwAAn2gu4w
	(envelope-from <jack@suse.cz>); Fri, 16 Feb 2024 11:43:37 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id A27A1A0807; Fri, 16 Feb 2024 12:43:32 +0100 (CET)
Date: Fri, 16 Feb 2024 12:43:32 +0100
From: Jan Kara <jack@suse.cz>
To: syzbot <syzbot+4fcffdd85e518af6f129@syzkaller.appspotmail.com>
Cc: agruenba@redhat.com, akpm@linux-foundation.org, anprice@redhat.com,
	axboe@kernel.dk, brauner@kernel.org, cluster-devel@redhat.com,
	dvyukov@google.com, elver@google.com, gfs2@lists.linux.dev,
	glider@google.com, jack@suse.cz, kasan-dev@googlegroups.com,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com
Subject: Re: [syzbot] [gfs2?] INFO: task hung in write_cache_pages (3)
Message-ID: <20240216114332.syzemwegji72j4uh@quack3>
References: <0000000000001f905c0604837659@google.com>
 <000000000000b06c9e06117db32b@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <000000000000b06c9e06117db32b@google.com>
X-Spamd-Result: default: False [2.68 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:98:from];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 URI_HIDDEN_PATH(1.00)[https://syzkaller.appspot.com/x/.config?x=3d78b3780d210e21];
	 TAGGED_RCPT(0.00)[4fcffdd85e518af6f129];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-0.01)[46.59%];
	 R_RATELIMIT(0.00)[to_ip_from(RL4bxzs479wr4ugdxt3xrjx6ud)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_TWELVE(0.00)[17];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_NOT_FQDN(0.50)[];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 SUBJECT_HAS_QUESTION(0.00)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 2.68
X-Rspamd-Queue-Id: 1903A1FB65
X-Spam-Level: **
X-Spam-Flag: NO
X-Spamd-Bar: ++
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=OCbMbtZT;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=e7U0D98d;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted
 sender) smtp.mailfrom=jack@suse.cz
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

On Fri 16-02-24 03:04:03, syzbot wrote:
> syzbot suspects this issue was fixed by commit:
> 
> commit 6f861765464f43a71462d52026fbddfc858239a5
> Author: Jan Kara <jack@suse.cz>
> Date:   Wed Nov 1 17:43:10 2023 +0000
> 
>     fs: Block writes to mounted block devices
> 
> bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=151b2b78180000
> start commit:   92901222f83d Merge tag 'f2fs-for-6-6-rc1' of git://git.ker..
> git tree:       upstream
> kernel config:  https://syzkaller.appspot.com/x/.config?x=3d78b3780d210e21
> dashboard link: https://syzkaller.appspot.com/bug?extid=4fcffdd85e518af6f129
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=17933a00680000
> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=12ef7104680000
> 
> If the result looks correct, please mark the issue as fixed by replying with:

Makes sense.
 
#syz fix: fs: Block writes to mounted block devices

								Honza
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240216114332.syzemwegji72j4uh%40quack3.
