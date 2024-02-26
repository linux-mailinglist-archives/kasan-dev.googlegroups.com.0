Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHME6OXAMGQE2BNCKUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 27529867CC0
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 17:53:51 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2d2549572e7sf25880551fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 08:53:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708966430; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y8IbNEE2IaQQaSq3fucJEesQu9qMQvp1jLC8pYeElTw07i3wfXPy1aTcA3EdaV+Nou
         qPU6lx5ON5CSqTdDSOGyUtwyEE+bdm+PxHE5U+iRFrEGCcaFsdsnATnheZ26fVThXHwS
         jlKrFAZUqw0TOW3Agn9QkbFgP8olNNbFllPBBNKg0rKkU4afyoaG3lEQzebrSL+SF3Xo
         zGym3v1ZH5luIi9Supnjpo4o1ayhbVbRNaY2ytfNhU1H6RiWGB2Jnsz1WCBCwVjDhPXD
         pJlK7OJ/JMS6QoMyCXybbMDiQYBRVxy2O6wyrf3geYbKQ/ASOLfhPkAR1+q90mws2BbJ
         17kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=NidOVAbPJsiVVwek2okXHhY0A+nKNxkIFG23eynaBM4=;
        fh=Chk+BzeAL6t4xOZhEPTUZhJSxzz0KejsgS2OtrFXL80=;
        b=yVMjpGbFd2gKIu0ztjntSCxjPcuLg1Z2hSBmoOIahAfHBwSomHgw7iWZ5e+vbVb2xp
         hWCG1KVWa8M2VC6pEdR3tcZeAXutHWOOFFdOuLE0eq2++gTl9qeBBxZiMQuhlEzCnXa6
         4QY27aS6pHURoLAYMPNDgcN1toaS2mU4JSYkq1u3luBPnH+vXuVqhN/nW530r+1If+dX
         Ec8jdrKsGp3orsOvVX+rf7vgZN8V7KKMJcXyVvHFFD1iTBi3AWeGLRrsxG2gFBS7DP/q
         WWlkag21w/CFgH+j6fHoO4RVpdH6zuLDoN2L+LKS9ryjMGm8Sy7EJrp5LbSvvJo+KRlh
         WdDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SC1Y7gg5;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SC1Y7gg5;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708966430; x=1709571230; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NidOVAbPJsiVVwek2okXHhY0A+nKNxkIFG23eynaBM4=;
        b=D0AUDJXXTAGcxTIQR2X5TBy3xaS9kn1OQ2Nh+KI21xo4+Boff5kW68jWUf9f5LEiDB
         qE2M4umzVEIefw8W9zy8kH/wWh9aY4lr9SrGMlysSlo/0chWgDW1xsQIJkwFEHx0Lxuh
         TQEsg8GIBRC9GHW5CtxB2x7yvAmWpjqNJHD+WhhQ+vof1YBF1qMg4xi9pWq7Pg/klHCo
         eoKattCZ50QKI6UKdMPXpHl3WBVDF75Mld3kBEv1hj2pJ8Yn4X70U+kvCtuT51WGdB9W
         9vzISFCNUQUe9ROaXxsig2zbzhCEmb24iKbq7wQbXqegL7x6a1j1cxnU2GEoAhalwAcO
         nCpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708966430; x=1709571230;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NidOVAbPJsiVVwek2okXHhY0A+nKNxkIFG23eynaBM4=;
        b=FGlYHvqtH0Qpb6CSfUeak3MDbRBwzJiZAO+TC1s8yQxFfiycZetqatS5nbVL3DkhCE
         D1LdAmSPtT1rG+0Bmc7q7KXp3uH/QT4HvF3Ca+NvEv2cM7rdTrIGY5jV3MMJ8530gCKj
         Cxuatc3cnT10G9x3fByuYmg3DNmSbHh/4p+obUi+IkFi+SgBCS2w4udhhVJ987hSwGK/
         bHPE36usSo4YzF8wnwExl5xyBoLioAmckJ7gMuTZ2lJ4yORfHgczRTVBGoCDE8SquTcO
         g/FS9FXD04rko4i0BtyI4wE2rtoxAUW4hDkWtF3wc/hLlWresv6I2y0jAGkNRV4lsaxf
         frIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUkFAUi8luuPnL/ssDprv54kXq7QXWUG/8TDTNf5d/qIy7WFfNdGAZ0DAaIHn8XIUx4qzuBOKRPWuHDhgNCPPPJkStbDPpkUA==
X-Gm-Message-State: AOJu0YwuCg3jS7lqW6CHqQ3oJgfEctLiiZ0DW851M3DQTGl5MfH33T+2
	/c6/34jPEiQvTugHc2uKUzzAFd55FC5YmpAcDLIw3RYAAwSGCIQB
X-Google-Smtp-Source: AGHT+IGdCsp8RFqZKOeY3P+jhC42/1zsJXdzUECy3CnsdkeWJ/QmDJfTRYmJ/pirwH0OeAXxYopuWw==
X-Received: by 2002:a05:6512:e88:b0:512:bda4:bf47 with SMTP id bi8-20020a0565120e8800b00512bda4bf47mr5259302lfb.4.1708966430166;
        Mon, 26 Feb 2024 08:53:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:104a:b0:512:d5cb:15a6 with SMTP id
 c10-20020a056512104a00b00512d5cb15a6ls313742lfb.2.-pod-prod-03-eu; Mon, 26
 Feb 2024 08:53:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWlLcgzxPreR8/q7AmFJJjj6iuxFUebaLqh2xR9X6N+rXEow3UelhHwIA8Oys5oVE6s9mhYdRln0GuigI2GnUZba8cnP669x1f6ww==
X-Received: by 2002:a05:6512:3a8e:b0:512:9c37:97fc with SMTP id q14-20020a0565123a8e00b005129c3797fcmr5563906lfu.57.1708966428336;
        Mon, 26 Feb 2024 08:53:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708966428; cv=none;
        d=google.com; s=arc-20160816;
        b=noeRQy0dJZ2ctADfSmWjufQCqCBrERr7jt61282qlFX1I1h2dMM35X1+j0j6Vzbjw4
         r7vuWyUhuo7kYUXMlo0T/DHF8PfC6zMMZxA26xjtLvZTN7UV/pGae0NK95OYF3ynaZRU
         DoFBpuM/9DP2uoPn2Z34kkITXefqkI3h4mB7S4PHcK1r/yGeMGERzo8Hqg5nU33YJG0q
         qPnNzQBo/r2miZQX3htDGlX28ZQJDNulnUTr2Sbi/8fuX7v196mZRfLQ7mNljrjtjgDh
         dx7UhUpamXM45aIds+qG6E4trrI3MVMQtWiCsf5oNS46fco+YwTpK9GV4b6P8/zMBib+
         Inlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=MgS/hvgxhSITdk7Ky5kATehTNmll0NfOjHtx26rdj8w=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=LD1fu5uKoU3KNLB1cBDjaSfpgXNIdp0CmYdIded7USWStPtVS8v1HP+g+RWjHDSoGc
         AoNTky8wi4Atg9T3amtzTXVLO+TtdgbqUV1i/BMLSod3KAHEpyTKBpuyn2FRYZmMCVV6
         7o7o5BR6OTfyP1WtAIbDaa7lMYoLk4Gj4xf+p1PD8+6zeX/++vl6WAxib9MWgTizBnVK
         Jv3+TA9COH65qhV4ATbPzxzweLaAB9iQyafC8XG/4mFxZPkMXqjdRuMHBIHhsQEJnqTZ
         PkIIW+zbFUgB6UPBjAAqvoTq36wiyWOrj8cyU4esgQKvLrrH6Ee9yYPqUXdq/Xo9A5HW
         NroA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SC1Y7gg5;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SC1Y7gg5;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id k15-20020a05651239cf00b00512f9756679si247110lfu.6.2024.02.26.08.53.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 08:53:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8D51222234;
	Mon, 26 Feb 2024 16:53:47 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id F076813A58;
	Mon, 26 Feb 2024 16:53:46 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id g9dZOhrC3GXKFgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Feb 2024 16:53:46 +0000
Message-ID: <fd480d2f-01bd-4658-b1b2-bf78383496f6@suse.cz>
Date: Mon, 26 Feb 2024 17:53:46 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 10/36] slab: objext: introduce objext_flags as
 extension to page_memcg_data_flags
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-11-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-11-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -2.35
X-Spamd-Result: default: False [-2.35 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 BAYES_HAM(-2.56)[98.04%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[chromium.org:email,suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=SC1Y7gg5;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=SC1Y7gg5;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/21/24 20:40, Suren Baghdasaryan wrote:
> Introduce objext_flags to store additional objext flags unrelated to memcg.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fd480d2f-01bd-4658-b1b2-bf78383496f6%40suse.cz.
