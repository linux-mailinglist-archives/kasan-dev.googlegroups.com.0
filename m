Return-Path: <kasan-dev+bncBDXYDPH3S4OBBG7KUO4AMGQEHWVVEVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id B1C3199A05C
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 11:51:26 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2fad1771626sf15947391fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 02:51:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728640285; cv=pass;
        d=google.com; s=arc-20240605;
        b=jvBg45iSjTWRTR2MftVniX/0fnEONon5e3VeCoorkPBeF0QDIb/aRAei893Bj0y4yr
         tTP4ws/DNk08PdC+py5bsM3DCKfocsyVdhOzGgKl3jcd+4wyKn44MkBhO+35XM0LfVFn
         wpHSwJPm0wlB+i24LD4eIGGOyYUtZGG10Rz9N8c5+3JdvaqkfedpDbm1OwzdpEjB4E4K
         AY139LpKLFg6W4h7RJL3iWv6DLCzsBNOBXTjRCac6rFJlGFNjkOeYia7UP8AoGGQjsUo
         kUObgHY9Ynq22FGCirfTC46udTaEesrUjTm6/mOOqy7phfLAg3bk1JB/NG0Zimy4eudF
         zFHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=QQOTUY9bUeK26KF7ecQwIHa38sG1yUHV8ZlZ1sfO744=;
        fh=02izXUyDtXDXCCnIv//6wUbFBEu2b8f9ELdMkn5Rcf0=;
        b=fKHdAg3izMEsdi3DlzW8hN9EO2tfZl+wcQN18AT2nVNQDg1E+A7lhCO9z+1RS5KRwb
         MPBtmJ8VIzZD6OLA0XU0FBEoEn0Br8B1skfgRH+Y+o5R/O6p+LHYWFMbsHSBi+ihKF1f
         oEr2vm/VgdWdbtcNWuIqR8TDwRGLF/0EEqy168qjSH+ybAkm8eJBOWH/bQhdzujgj7vt
         MixhY2vZl2WFCSSIQWcsDB5YFxBLXqIL6dObSXk7Nn3+56fQthPPqkGYbreszpPTe1et
         ox9yzU9WvKmH+5hwTNy1F0dHHZ0qZufrNETZHgTjJAfcgmXLeY6rvzrvdjkoPjveHvw/
         61vQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=sOQlE3CM;
       dkim=neutral (no key) header.i=@suse.cz header.b=NsyPkt5X;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pzjC3EbI;
       dkim=neutral (no key) header.i=@suse.cz header.b=1PdmC6hk;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728640285; x=1729245085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:to
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QQOTUY9bUeK26KF7ecQwIHa38sG1yUHV8ZlZ1sfO744=;
        b=pUxwLMoKSpu2fnP76o8j0DcFboMvHUcdjoFYtEIGU5K8tqdjGQdFN+c1KYJY4PT2uX
         3vXX4r/CI7x73t9EPrIE46rbMWQ9xt2SeTzIK0nUA77Nrn0D0mla0lmMAimGivpBDRa/
         BqOpSU6QHZDtw0I9C5MWj74Rqs1XZfJHUox6Uhh3nkkaOeJQTM45CzPcKVx6KFr+5sex
         Mwa2F/aQgSGSSVXZgrPHtMXjNrbUxmGuCDmeHJS404rRCIYT+L5BeNsir9LdqkYEdjCS
         xdZmk/Z2FIIpbSbVh0sEaQeDu2ZQhvDpuDcY6OLs1ArORTIFpbd4iZYYqFjAIVn2l5wC
         qAMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728640285; x=1729245085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QQOTUY9bUeK26KF7ecQwIHa38sG1yUHV8ZlZ1sfO744=;
        b=Qsr1m97Whl4sbotHHHHSyHZ2bxDSVOhAmfbDPa7DM+k2Z/smvpx+uUNmG1bigm5gWV
         E5BUAG8VyB3Y5u/jejCzdc9IvlpBwKJEOfH7hvX+1noYP1XLKMVghv8TW1cIbnlqvlLH
         9nw52gCWAkNPS0hHtgFHHCHSwHtSdMCzId52IMe2qKbV2PgVYXabEC03DY3bQ+b31x59
         T/sNbGDX5b6GDUfozZKwPbexvyWvpOEqtak8BJe1wuEMjdozthBvDWYkB2NoAPh73NMH
         SwUoX+HaC5wq6ZA6ZQaIgk0VZXLuNl/0+3bUKlGqA2GcwqQ4CklkWpAbrcId8iwHm+Eh
         RiOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRlHPV+XZgzgwexhHI2725ZZbGNMhyw/CQMQG157EqiTSAAAfulVn2Kp4FA6u9P+MmZgIQWw==@lfdr.de
X-Gm-Message-State: AOJu0YwP58ZCtYwfgyPjMmbaVC1Frd5StOpodc1cy7msgp9yr+zcUvGU
	Ju+gTunjYjYBHSyE0XXsqHI51T36JB6iEFlUMu72I0Uns/evPXUB
X-Google-Smtp-Source: AGHT+IFKx3d7L0jXVaWE+Z6VF2Ggm6R0GPA5NPGMCurtlzSnhMNaWwjz+f4ZBQOkbWRbUoU8WLbjMA==
X-Received: by 2002:a05:6512:3088:b0:539:964c:16d4 with SMTP id 2adb3069b0e04-539da4e2d3emr1028953e87.36.1728640284176;
        Fri, 11 Oct 2024 02:51:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a8:b0:539:9436:c105 with SMTP id
 2adb3069b0e04-539c9bd88f5ls1002981e87.1.-pod-prod-06-eu; Fri, 11 Oct 2024
 02:51:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFCSaJkZ6CKC5kgG+47BoVexWNxWeRiRXcwDuMCocF9oRLfeteAAKjFBF1G82fOr5ZkWm//7nUN/E=@googlegroups.com
X-Received: by 2002:a05:6512:2807:b0:539:9527:3d59 with SMTP id 2adb3069b0e04-539da58b34cmr1149286e87.52.1728640282206;
        Fri, 11 Oct 2024 02:51:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728640282; cv=none;
        d=google.com; s=arc-20240605;
        b=U1Xznfaa8DfY6oJogT0S+nN0hDqv23nWyEtxPwVBPFTcFlEOig8euk6oMt+z/WZwcH
         1UkJtrsmGw31HONTDkQzWOaGfp49zKbK6iYV1jkF05bb/INUEIifJLGP/wOtkEsPI5YY
         mSzUIPhGhot+3uPuPX6e4EluSqIjs+3D4V1zBQ7oUqwb5i98kAgy9WqUhiTwyA565nVG
         rVPwikj3qzYVFrAhrFdLjo+XVzmKMZADyQ9l0ujMMBF6rOQD/ElHBWNrOzTidPtN5cs4
         6v/GEEikR/QaMNwNwxa9c+PIxT5zdOP5nbzwjh2fx9fFXsFfrzrSclkprfKvXg693Zcl
         KYeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=M3NVgG2SICKyUPtdW/rnnVkSJXEFp2qEVc5fEtUfRD8=;
        fh=EsnMOP6EjAV1U/ytsLBP06xTc4Dc+mHIWF92a8+jYk8=;
        b=j+RUFxfw+LbnqM1zchtdypELGscePk+le/mWGDorlAi15v9VQeSztyoxw+EV5fo+eO
         Nzz0xHI6L02LuPUJNFQgJZYIuGOqNx7mcdAG6483AAgTwJZ6aR1HVkBxXILFKIWMW8TC
         ehxLref92aL4+A8GF+PIfF5HgUDzt6KhVv0MKcpveeOVk9aX55oi7dquNl0o0abJiwT8
         4qDfAuhJrjNX603t27TsCjxYKpDmTXRZKGweW3TPGZ7ygmJZA05iP7G0Hmt7ePD/xvKo
         vQvoq1ZPCP8KF9rGEoKLPXgv5j9VIYMp1l+hd8xVHo5u+8ImtFylD4tfSRXvc+y5K6ap
         0MUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=sOQlE3CM;
       dkim=neutral (no key) header.i=@suse.cz header.b=NsyPkt5X;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pzjC3EbI;
       dkim=neutral (no key) header.i=@suse.cz header.b=1PdmC6hk;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539e314b5aasi2582e87.7.2024.10.11.02.51.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Oct 2024 02:51:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4AF9921DB3;
	Fri, 11 Oct 2024 09:51:20 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1F88C1370C;
	Fri, 11 Oct 2024 09:51:20 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 3go4Bxj1CGdxNgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 11 Oct 2024 09:51:20 +0000
Message-ID: <c8dffa25-4fb4-486a-9587-1c7359457abc@suse.cz>
Date: Fri, 11 Oct 2024 11:54:05 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [syzbot] [mm?] INFO: task hung in hugetlb_fault
To: syzbot <syzbot+7bb5e48f6ead66c72906@syzkaller.appspotmail.com>,
 akpm@linux-foundation.org, dvyukov@google.com, elver@google.com,
 glider@google.com, kasan-dev@googlegroups.com, keescook@chromium.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, mcgrof@kernel.org,
 mhiramat@kernel.org, mhocko@suse.com, mike.kravetz@oracle.com,
 muchun.song@linux.dev, syzkaller-bugs@googlegroups.com,
 torvalds@linux-foundation.org
References: <67084cfa.050a0220.3e960.0005.GAE@google.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <67084cfa.050a0220.3e960.0005.GAE@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: 4AF9921DB3
X-Spam-Score: -2.01
X-Rspamd-Action: no action
X-Spamd-Result: default: False [-2.01 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	URI_HIDDEN_PATH(1.00)[https://syzkaller.appspot.com/x/.config?x=fb6ea01107fa96bd];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	RCPT_COUNT_TWELVE(0.00)[16];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	TO_DN_SOME(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	REDIRECTOR_URL(0.00)[goo.gl];
	TAGGED_RCPT(0.00)[7bb5e48f6ead66c72906];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	SUBJECT_HAS_QUESTION(0.00)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=sOQlE3CM;       dkim=neutral
 (no key) header.i=@suse.cz header.b=NsyPkt5X;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=pzjC3EbI;       dkim=neutral
 (no key) header.i=@suse.cz header.b=1PdmC6hk;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/10/24 11:54 PM, syzbot wrote:
> syzbot has bisected this issue to:
> 
> commit 3db978d480e2843979a2b56f2f7da726f2b295b2
> Author: Vlastimil Babka <vbabka@suse.cz>
> Date:   Mon Jun 8 04:40:24 2020 +0000
> 
>     kernel/sysctl: support setting sysctl parameters from kernel command line

Hi, I see you have a number of sysctl options in CONFIG_CMDLINE
including  sysctl.vm.nr_hugepages=4 which seems necessary to get a
hugetlb_fault. And without the commit above, those sysctl boot options
are not applied. So you'd have to handle sysctl differently to test any
commits earlier than that one.

Thanks,
Vlastimil

> bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=1499efd0580000
> start commit:   87d6aab2389e Merge tag 'for_linus' of git://git.kernel.org..
> git tree:       upstream
> final oops:     https://syzkaller.appspot.com/x/report.txt?x=1699efd0580000
> console output: https://syzkaller.appspot.com/x/log.txt?x=1299efd0580000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=fb6ea01107fa96bd
> dashboard link: https://syzkaller.appspot.com/bug?extid=7bb5e48f6ead66c72906
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=17dd6327980000
> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=16d24f9f980000
> 
> Reported-by: syzbot+7bb5e48f6ead66c72906@syzkaller.appspotmail.com
> Fixes: 3db978d480e2 ("kernel/sysctl: support setting sysctl parameters from kernel command line")
> 
> For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c8dffa25-4fb4-486a-9587-1c7359457abc%40suse.cz.
