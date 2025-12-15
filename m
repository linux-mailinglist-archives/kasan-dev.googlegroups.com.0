Return-Path: <kasan-dev+bncBC5I5WEMW4JBBVULQDFAMGQEEKRBBTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EE09CBDEA4
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 13:58:00 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59584152ed3sf3298542e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 04:58:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765803479; cv=pass;
        d=google.com; s=arc-20240605;
        b=MpQWSJGmw3UP7YhEOOAsFyGd8Jb0Br1y5hidjawRemrQyqHmyZm4ROd1GdHDPURWem
         InOCBnpOkv21cBlJnxysgVwsnOyLdfB/hxnGllt+fG1L7szQvM2W7CftvgQZtHQDJALC
         RuLqCY413xJHN+tLXxaA8RmnRtYX+JP6nJ6gTHBy23cxRduNgVUW99OgBuhetloShXWk
         U82CazwoAPDFD7pW7IYKfqwgG/EoYRkmRZQT4W+yPOt/RcL1sj+3J4CYAdqVi3powx7p
         pcmZFjUaIeKSLJRRY87NLvvGjrwsAW238wrunk/oJa9BHPQuaP8Vq7TscSkvKZ72U/2t
         +2Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/D4ikWUMbHfdz++yspYp/OwKJJUqkfikB2x1MLl8LI8=;
        fh=Or2akn5xs5/GVIxbq+t5lpaiP1TO4Ez305LSfEN09yI=;
        b=BzVPVFz1j7Z76przVy6xhaKb17bpb6OmG+MMGqLEMP9fYyBLZF4/zBsRUAg71jG9zP
         xMgsDh0mWde79ymaUhyDr952g8SF/FVWZGYWkCPO5kiHd90PVjJn6h7DrDpkwQeJ0C0a
         4FV6r42VUA3O4Yxgw3npjrzXG6KX8QhnbiiNWGC3fiw0KHElBRm8XAyGynhIuogMiWI9
         f7yB3tplqYcB3Nkt2jRTnkFLwhFEn+dB4PMti3u25ACbXz6qMgqUPWbtGS8GHRkwjc+g
         ayWvJ6Syg+4rW8KeiytwcorqyZ6p8kSRUVnm2NTFvff0NvSiwXm9CxSbNZPXnrX1Ntec
         /KOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wbudG5tR;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wbudG5tR;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765803479; x=1766408279; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/D4ikWUMbHfdz++yspYp/OwKJJUqkfikB2x1MLl8LI8=;
        b=RyI8JSpnx0z4kp4zX/JHpB/UMygGwC/ZN8xJos5xmI9XwY43Aj7oW4OmAAnDb22H6c
         4G075XfQjw0Ff51mfGVnah0mIUemVdCD1qkVgoYvsDX35IOt612d/8iVjGyg/cxUAugP
         oRPkCt5FKlgq8MsNNu5N7HVY/iI9lMJq5kk4TJKj9GD0x4ZM28csI/57Goi4djmIP1tf
         Kjq009BfEF/PxDqz/JggcXI3afH/9MU0YZH/47GqgoIczpvNgo/uYKdSGTaiysMt4ZSh
         npa72BQDFA+3OiKIKUuqP51OL0wE2gg2pKX+mHTNR6ByZciVUm8HziJqywSO76to98Lm
         /ZJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765803479; x=1766408279;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/D4ikWUMbHfdz++yspYp/OwKJJUqkfikB2x1MLl8LI8=;
        b=F4bxhM9ryykQTpfNMIiS9aGw0VYyrF89p28vODRjEU2i4DpHHTLlpbr2nFYnB6qPtu
         m0sytaiUPGu2Ri/YM2tWLS3TftSVTc4TBroA07JIXnjRav85y7DD2RdsaAm/bk4IVl/S
         R0X/fCzMXEafqFwo99zA5F+UDRnfloJW3NfhtNZIPtGWhnslWQtMkNO/aIaj8ZUyj0dj
         /ztZ4KGRvcYzuC3B2mN6j9M5S7xyXszXiCxHGk0MltF2S84XBREsWbrsM7iLxmuUpDNz
         In92MuFmz0i0iXXDJXXBYsJZ4b2BRmWXhD0HUTfuVMnsHl+sUxQ3si3/y52cGVNKuZXv
         jl7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXp8aaUpxlaUnpONYcJ43m+UoaIQppawJFuyXIRMIaq8ce3mIZxgkG0jG+4Uqb4QLSCMxJfLw==@lfdr.de
X-Gm-Message-State: AOJu0YwW+kO3BuGEVw0dZ5nGkdd59w9V1N6BPUl/NS+tO2sQw7xaYJKz
	t2BQwdDIcE18XJ3nR1qlAPbYHF5o5z/zP7ftVCc5nYZdohQpuHymjUhq
X-Google-Smtp-Source: AGHT+IHt/1N63bVQtUO4PU+lRw0hHHq/b74Ma/molL8oHFYt0454Npi5RuPgLIo3xbCJ2Gb/aGx8UQ==
X-Received: by 2002:a05:6512:3d9e:b0:592:f27d:75d4 with SMTP id 2adb3069b0e04-598faa963ccmr3810744e87.45.1765803478980;
        Mon, 15 Dec 2025 04:57:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaocXPgS9qkLhSdWGYxwelJRbkmDvVORAtdfqcNA9tXVA=="
Received: by 2002:a05:6512:ba2:b0:598:f802:e2dd with SMTP id
 2adb3069b0e04-598fa391dcfls1254219e87.0.-pod-prod-04-eu; Mon, 15 Dec 2025
 04:57:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzZ7YE+B71x+rMMBIOcxmrZIo6ldi4uEAq18jHqrbZ8Cf+UrRBeVIxWY9ur4e0Y5KLIC3Lhzgj22U=@googlegroups.com
X-Received: by 2002:a05:6512:1329:b0:595:7fa2:acf with SMTP id 2adb3069b0e04-598faa812femr3869813e87.31.1765803475637;
        Mon, 15 Dec 2025 04:57:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765803475; cv=none;
        d=google.com; s=arc-20240605;
        b=Ar53teTTQ8D1tf3335D0//Z7BVLt0VN7VZ4MxaSUwpoxz6zf6Ge+bIWwX1yDq74rk1
         0Zhb4teo283G5v+4h8TgHLTleU15NK51dYVmSjZdcSkV2wP7FJvzPyuxXSi2GD/sgnzp
         AR+No2OAOo96naaMbqwCyse0mDorzO7aMV2SKx6oc+a9gtv8YkqaXqejRxodxmCweL9B
         1YI+QUn2ZKwyXIpLqqv30K+guJ0LDlCOyDpyLkndUelt+m0WaqpcEUMUIncoCtoy3uRI
         1yopr1l+lPIa2f+dCnt7dZljMEZe5bQom3ePUbl5B/1ZQAF0uHVbOncX4rzhCfthLHdm
         KHHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=+MMpU8iu26hMrIy/s70C2uUD4P60923K9CkgBqEJuQM=;
        fh=Wjtrdi6kt+DV7g7IoT9YyWgpghdwa0WQKy5U4JKLHgs=;
        b=Dn7e3OtN/5q41RaJKdOAc77+RNZ3uIyLt8n6GbifLpH111jILjvjQIBgvQn4Ve5+2l
         4OqZEMYxUsLLXeAkSqOg2adWHAjKgJ5AUdP2ZyJ40RLroqLn+nt6/9fiJb/7w1rvwI+E
         yEd5425/dI7Lb5VGFGI0Mxgxn9wke6s04d5TyZNFQZuzCPXotEvrQCKk22YPzvXm4mW6
         Fcz4/BJl3A9lmtfbYaDNmcRV/ohG6MietSZhvaKCNR/HDNK1Kk8pFNYcWOYpH5Cq9qsw
         gs8zzsi78BCUq4fAt/adznLB7K/pplkCpPWutpsc2Gwz59i2pTfNwzEp9oSFd69ZaCl/
         sYGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wbudG5tR;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wbudG5tR;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-598f2edeb14si218571e87.0.2025.12.15.04.57.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 04:57:55 -0800 (PST)
Received-SPF: pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C48955BDB5;
	Mon, 15 Dec 2025 12:57:54 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AD2CA3EA63;
	Mon, 15 Dec 2025 12:57:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id wPZAKtIFQGkgTQAAD6G6ig
	(envelope-from <jack@suse.cz>); Mon, 15 Dec 2025 12:57:54 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 6303FA0951; Mon, 15 Dec 2025 13:57:39 +0100 (CET)
Date: Mon, 15 Dec 2025 13:57:39 +0100
From: Jan Kara <jack@suse.cz>
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>, Linux DRI Development <dri-devel@lists.freedesktop.org>, 
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>, Linux Media <linux-media@vger.kernel.org>, 
	linaro-mm-sig@lists.linaro.org, kasan-dev@googlegroups.com, 
	Linux Virtualization <virtualization@lists.linux.dev>, Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Network Bridge <bridge@lists.linux.dev>, Linux Networking <netdev@vger.kernel.org>, 
	Harry Wentland <harry.wentland@amd.com>, Leo Li <sunpeng.li@amd.com>, 
	Rodrigo Siqueira <siqueira@igalia.com>, Alex Deucher <alexander.deucher@amd.com>, 
	Christian =?utf-8?B?S8O2bmln?= <christian.koenig@amd.com>, David Airlie <airlied@gmail.com>, 
	Simona Vetter <simona@ffwll.ch>, Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, 
	Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>, 
	Matthew Brost <matthew.brost@intel.com>, Danilo Krummrich <dakr@kernel.org>, 
	Philipp Stanner <phasta@kernel.org>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, Sumit Semwal <sumit.semwal@linaro.org>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, "Michael S. Tsirkin" <mst@redhat.com>, 
	Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>, 
	Eugenio =?utf-8?B?UMOpcmV6?= <eperezma@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Nikolay Aleksandrov <razor@blackwall.org>, 
	Ido Schimmel <idosch@nvidia.com>, "David S. Miller" <davem@davemloft.net>, 
	Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	Paolo Abeni <pabeni@redhat.com>, Simon Horman <horms@kernel.org>, 
	Taimur Hassan <Syed.Hassan@amd.com>, Wayne Lin <Wayne.Lin@amd.com>, Alex Hung <alex.hung@amd.com>, 
	Aurabindo Pillai <aurabindo.pillai@amd.com>, Dillon Varone <Dillon.Varone@amd.com>, 
	George Shen <george.shen@amd.com>, Aric Cyr <aric.cyr@amd.com>, Cruise Hung <Cruise.Hung@amd.com>, 
	Mario Limonciello <mario.limonciello@amd.com>, Sunil Khatri <sunil.khatri@amd.com>, 
	Dominik Kaszewski <dominik.kaszewski@amd.com>, David Hildenbrand <david@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	Max Kellermann <max.kellermann@ionos.com>, "Nysal Jan K.A." <nysal@linux.ibm.com>, 
	Ryan Roberts <ryan.roberts@arm.com>, Alexey Skidanov <alexey.skidanov@intel.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Vitaly Wool <vitaly.wool@konsulko.se>, Harry Yoo <harry.yoo@oracle.com>, 
	Mateusz Guzik <mjguzik@gmail.com>, NeilBrown <neil@brown.name>, Amir Goldstein <amir73il@gmail.com>, 
	Jeff Layton <jlayton@kernel.org>, Ivan Lipski <ivan.lipski@amd.com>, Tao Zhou <tao.zhou1@amd.com>, 
	YiPeng Chai <YiPeng.Chai@amd.com>, Hawking Zhang <Hawking.Zhang@amd.com>, 
	Lyude Paul <lyude@redhat.com>, Daniel Almeida <daniel.almeida@collabora.com>, 
	Luben Tuikov <luben.tuikov@amd.com>, Matthew Auld <matthew.auld@intel.com>, 
	Roopa Prabhu <roopa@cumulusnetworks.com>, Mao Zhu <zhumao001@208suo.com>, 
	Shaomin Deng <dengshaomin@cdjrlc.com>, Charles Han <hanchunchao@inspur.com>, 
	Jilin Yuan <yuanjilin@cdjrlc.com>, Swaraj Gaikwad <swarajgaikwad1925@gmail.com>, 
	George Anthony Vernon <contact@gvernon.com>
Subject: Re: [PATCH 07/14] fs: Describe @isnew parameter in ilookup5_nowait()
Message-ID: <qxbixswc7daxb3y7o7ebmy34dpa3uv6i5vc2fnj2p6f3sckulk@vcbuzldig7al>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
 <20251215113903.46555-8-bagasdotme@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251215113903.46555-8-bagasdotme@gmail.com>
X-Spamd-Result: default: False [-4.01 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	RCVD_COUNT_THREE(0.00)[3];
	ARC_NA(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[vger.kernel.org,lists.freedesktop.org,lists.linaro.org,googlegroups.com,lists.linux.dev,kvack.org,amd.com,igalia.com,gmail.com,ffwll.ch,linux.intel.com,kernel.org,suse.de,intel.com,zeniv.linux.org.uk,suse.cz,linaro.org,google.com,redhat.com,linux.alibaba.com,linux-foundation.org,blackwall.org,nvidia.com,davemloft.net,infradead.org,oracle.com,ionos.com,linux.ibm.com,arm.com,linux.dev,konsulko.se,brown.name,collabora.com,cumulusnetworks.com,208suo.com,cdjrlc.com,inspur.com,gvernon.com];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCPT_COUNT_GT_50(0.00)[86];
	MISSING_XM_UA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLuzgdneaas1ufq3krk51sbiga)];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:dkim,suse.com:email]
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Rspamd-Queue-Id: C48955BDB5
X-Spam-Flag: NO
X-Spam-Score: -4.01
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=wbudG5tR;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=wbudG5tR;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of jack@suse.cz
 designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
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

On Mon 15-12-25 18:38:55, Bagas Sanjaya wrote:
> Sphinx reports kernel-doc warning:
> 
> WARNING: ./fs/inode.c:1607 function parameter 'isnew' not described in 'ilookup5_nowait'
> 
> Describe the parameter.
> 
> Fixes: a27628f4363435 ("fs: rework I_NEW handling to operate without fences")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>

...

> @@ -1593,6 +1593,7 @@ EXPORT_SYMBOL(igrab);
>   * @hashval:	hash value (usually inode number) to search for
>   * @test:	callback used for comparisons between inodes
>   * @data:	opaque data pointer to pass to @test
> + * @isnew:	whether the inode is new or not

I'm sorry but this is true but misleading at the same time. I'd write there
something like:

 * @isnew:    return argument telling whether I_NEW was set when the inode
              was found in hash (the caller needs to wait for I_NEW to clear).


								Honza
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/qxbixswc7daxb3y7o7ebmy34dpa3uv6i5vc2fnj2p6f3sckulk%40vcbuzldig7al.
