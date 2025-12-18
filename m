Return-Path: <kasan-dev+bncBCJ455VFUALBBMPDRXFAMGQEB32QBOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B3E2CCA27B
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 04:14:59 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-88a2d8b7ea5sf2294586d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 19:14:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766027698; cv=pass;
        d=google.com; s=arc-20240605;
        b=PILlVRLK70+kXVI9CyVlvBhHlxETj77R7p6TsuP4gEuVPuMxs9Tkjmplh42si476TX
         ySRS4byHLvLhlZaofqpE0CO1sYYlwAzsfKeTwhySMvyRzIS4ZEiss1HKlGAaOspMspYo
         8J9+okBNEKoA/W+LQoptTdRhTkwMjDjnTy6diKcKWZinfR1NtFVYYSAmHiWTzQg16cOM
         q16vPLwGtO8uX+6Tvpo3F0eJVEhZXFoE7yuCmNht0tEu2lfNdW+1ib67y65TYzP0/l7/
         /S7P+t1vx/u6FwbeqKMxhgFiX76/zQwe2FvaEUFBbKrSuFnKVAWEqD63w5yt5StwXtTZ
         MV8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=JfEunnWcFCxKuhxmhwOuxhaCp9AxbCdV3TfPPncsGVw=;
        fh=tvJlNuIfXjEDFCW67FXMFqxY0k7GHtyhSu7RmA6qtcA=;
        b=X+/UQbEnRbzLmWrfaRXAun64eXuZcDH9uoZWj6cpPIkChPqPJ2m9xXhsIMct6t6z7S
         ea5PJHHO52Wd3nlVIBmGuilry5dVZVzV6tedNurQpPV/1Q5DvBGWa4jqvA100p02zFgY
         gbgvS9lz5wVezWho0n6fK/BY/Qfp4ke9ledhxNBkB+bHEYNBhf1GA5HemRQp2Z4eqcx9
         D/MgzpXCYpOLe0yxza+AwnRuNnMrnYELwu4x60L1oBrCT8Fx1spMgGYmyP1b48SE1u2k
         floUHKSN0fAV1goI0KDqrGOMZdjjeX9OjurFXg+dOAdrKGbhZAsIWaxf1mybLekCkMjq
         s6sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eGLGT95r;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766027698; x=1766632498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JfEunnWcFCxKuhxmhwOuxhaCp9AxbCdV3TfPPncsGVw=;
        b=f8KQCXbDo4A9uIjxkLG+7H4jHNkJDz5cEKzkt8BcNhA/gW3sSAA/GxT05Kzl8hlMHl
         ODMvuxDVSKC3YIxcpRVoG2NhaNfM79j9OTlBxKhZf8QEoySnqwgnIAxlSH/LP/X1QBuE
         uYItiMfuWRpPSrN6ReLW87VGW0tLuTNyHcxq5R+PcN1eGiNvPcUxUbfrZf4OVwPZS30D
         hgSmP39xlQrEf+E531kVsoAaHXmWwNpxHCzCCH2feiyn0Rxlm/OLfeJf6ExKh5eVRqDK
         s1cQqT99NEU5rOID4ULgChwAZgOGO2oC3yGiw3xnwagARpTN18JQXthlvg0cUdKtnhb9
         1cCw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1766027698; x=1766632498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=JfEunnWcFCxKuhxmhwOuxhaCp9AxbCdV3TfPPncsGVw=;
        b=Ugi9v3+uNN5NwE+OpvzfD5e/ThnKbLxA5t/QIU/I6dfiRdyaM4A+FQpd8qBiOJr45m
         mFeVAkydChJIDjycZo2wpKKaOuIA47ws38qj0c4wuhH75Zg+sDZhijGCRkTfEm4Birsw
         VxE+Ck5CeCcZSv/aKQdEqzpSXcZDYX+J0PKWRhMlZ2fuueN8NhXjXe+HGAKWzyflnGYJ
         lj+yL5rL+N/eZo+54Qs+m2jzZu+QZw270BVYwvvuCwwe19+NH67yTsAypuaDWF2qjkVv
         PjiyuLEyCcQY1Zhfz1hfmwnpZtO58SVZe8Tq7AXokvHDPcBtWAj66bUJdHop+RUi4Aqh
         2nPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766027698; x=1766632498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JfEunnWcFCxKuhxmhwOuxhaCp9AxbCdV3TfPPncsGVw=;
        b=cKBOqv/EmkYv6Vau32w2abJHsSjhWIQ406oZDhiHG9sAkmFx+tgG/Fkli8CquF30lA
         6BmCr38+kV3lh7VtRy7PweU0MrVkj+RuNMwEeZ50+BckBWahhBAqzM4oSgiXKBGc1mSb
         LfXo2tV+cKMdVadrkepdI07TAjbqWnO+r0ZWxpXWMqYGLnEWnrEXx/HEQon3YZgIVr3c
         RgHKSa53bhZgybh4EuN8Nnm+l7yMgoXTcBZSHAm5Gtdc96IMsKIdeoo7MVDaDD1tBVn7
         oP87T9x+CtZ4H+IyfDHKhfxBw6Q+W7Uo3vUs47M5ISYaMnz4z+wr87QFCX9Au1xbsTNp
         mhLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWTNwLYV2briGuuHyt5fSGt4VKRcNWg2uBnN18KTuSTCbiT3v6CIDYCYlLDk+Auem+Akx65cg==@lfdr.de
X-Gm-Message-State: AOJu0Yybr3W6tL5nVvJfTmksBAvoSMTsbmt7pYVqDRHSAe83MwDM64NH
	GnovyZoLr7bEFc1T4BZlPDj3cYPllNAIPqHMZ6H6h46/IohkMi9oe3+I
X-Google-Smtp-Source: AGHT+IHJpbczY7CFT6hc8qbHpBManzOSglMGKZ0wC2Vi5/unxA0DZvVPEqYhNtuPsc76NMBpF1LLzg==
X-Received: by 2002:a05:6214:5b82:b0:88a:277d:10c with SMTP id 6a1803df08f44-88a277d10a8mr203534976d6.26.1766027697967;
        Wed, 17 Dec 2025 19:14:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYyV0VrhsEeA87PyJvs0Jjcxy8Mt8UvrejllZvg/naezw=="
Received: by 2002:a05:6214:500a:b0:888:3f27:d2e2 with SMTP id
 6a1803df08f44-8887cd8938dls105110616d6.2.-pod-prod-08-us; Wed, 17 Dec 2025
 19:14:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX+DUopfbgZNAx0G16PBsvcd45lw5KUORTXS9yb1aDZEKA1UQEyKAn4Oav3DcivKNUtnJXjqvN7ZPg=@googlegroups.com
X-Received: by 2002:a05:6102:4485:b0:5dd:c569:a797 with SMTP id ada2fe7eead31-5e8277b1e85mr6089620137.23.1766027696516;
        Wed, 17 Dec 2025 19:14:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766027696; cv=none;
        d=google.com; s=arc-20240605;
        b=V6Mfqe7ip+fverjHMVbYJWIjtd/oobe3QtWHT6fsBHmqSa/pwow6T/cDQiewcJ5Wmf
         A0BVBzLmL9KNpeRvuKuEp/oaT5lSSvU7ryen2mCwP8lr2uJAK1S2B1PNP7ZYJdBomqmQ
         e08HEMmntmDsVYDsEpawtnbSlVGQKIYIpwrtN5OfjUlA0aAdQFSdHUeP9RYJlWCSpLP2
         yRIKny3CgEe/oX0kT1PsfuMYlSgtP2uJC2qtl3R9SMrnLH+pMA/M3Celj2VvWqgS0ieS
         tT72o+MfkcksBte3WFRiD/EMp0WqlxYMSaAwRiiVDF04JDqlnTsG0u0sZwXM6RTLcw2G
         wa6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=aMmDsg6PeqY3yDJKla0eomYe6OESw8tJFHAPUF0WDJQ=;
        fh=8iT8m7VSbM/9OXpq7Gtz1GjjZrAbOz4/A2toI5eWe50=;
        b=lbCfLa4mCS2tnZXHtg1MZvvS0OLkoKqPXzgWK2RgpiOdJrJNJz9X4tBfLFG+iBaRtF
         2rx0eH9fgT864UdGXMULAC23Qx57jgSNjk2USEITVVKw9hZhr6j9Nk2q6WJfKoy6D5f/
         UDl0TO+q4XWLKI3Ka12OfPjujO/xrNmZeHhjrMrZM/QEpp5VjRmjg+i23QSQ4awnD9oa
         cxb1sLgZ1b4LjwByVw6Lxni6xABhRKter/RaalkH6dOjUPNHjc0qFuG1RYN7ZUEenQsc
         XeULFkQ2J8rx/w5VbWuPAvEYTRkRQfBL517IQ+OxgI+QsihjWO/O5C7QOLQQmkdChaWk
         YpYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eGLGT95r;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5eb05963411si16635137.2.2025.12.17.19.14.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Dec 2025 19:14:56 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id d2e1a72fcca58-7bb710d1d1dso377594b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 17 Dec 2025 19:14:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVrDHvYlBAUNCON4Mr60pLe9isUINGhGLfFzRdJHbPN9X+CNx2OftF4AAb1fBIDDZcbvpEUXxgsyNE=@googlegroups.com
X-Gm-Gg: AY/fxX4Nd+EggKXJ7DOxKAtU9s24L47HYsWCCl9RUoMT3jj1IZfuC4uTawO0O1S6aJA
	jhEbWC/3dbqFfdDlQTjWh6XlIGL+6st6kaB+Fw/zjpvEmmgLMGLtg+exRxpkSxOKiL0V6GpL4vF
	AUrlWFSdpl9KMmBefU6B1bSXxPIhKMAf8rebNZCQuvBjiw1HCEmwTEjvevkttKWm9eLN16VN0Te
	iDT1kTiWmQIXRXSg65lW30lC4CM8sGA3uHYH80MvHmbXOzoxtqCJL9cI0lU7ATV6sVeeTnCiIut
	q9/KtyXOJIosxaXlO/aKXwKg2H2T1HZkb6g7wmjYNcdY8yqxj6COzCV1hF9lBIJc3rUpb+zyoKS
	gryvBTUdkBRtdcpxhk/km6r4LU1Ovp1Ue8qM9gx1Exxune+d0WjjGxb6CJuLsNL/Tv/hJs89IIA
	0fVHJQcw3dkoleTbJRJ75Fcw==
X-Received: by 2002:a05:6a00:b904:b0:7b9:d7c2:fdf6 with SMTP id d2e1a72fcca58-7f6679326b4mr20199697b3a.24.1766027695319;
        Wed, 17 Dec 2025 19:14:55 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7fe1212551asm860633b3a.22.2025.12.17.19.14.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 19:14:54 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 75FB1420A930; Thu, 18 Dec 2025 10:14:51 +0700 (WIB)
Date: Thu, 18 Dec 2025 10:14:51 +0700
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Jakub Kicinski <kuba@kernel.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
	Linux Media <linux-media@vger.kernel.org>,
	linaro-mm-sig@lists.linaro.org, kasan-dev@googlegroups.com,
	Linux Virtualization <virtualization@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Network Bridge <bridge@lists.linux.dev>,
	Linux Networking <netdev@vger.kernel.org>,
	Harry Wentland <harry.wentland@amd.com>,
	Leo Li <sunpeng.li@amd.com>, Rodrigo Siqueira <siqueira@igalia.com>,
	Alex Deucher <alexander.deucher@amd.com>,
	Christian =?utf-8?B?S8O2bmln?= <christian.koenig@amd.com>,
	David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Matthew Brost <matthew.brost@intel.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Philipp Stanner <phasta@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?utf-8?B?UMOpcmV6?= <eperezma@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Nikolay Aleksandrov <razor@blackwall.org>,
	Ido Schimmel <idosch@nvidia.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>, Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Taimur Hassan <Syed.Hassan@amd.com>, Wayne Lin <Wayne.Lin@amd.com>,
	Alex Hung <alex.hung@amd.com>,
	Aurabindo Pillai <aurabindo.pillai@amd.com>,
	Dillon Varone <Dillon.Varone@amd.com>,
	George Shen <george.shen@amd.com>, Aric Cyr <aric.cyr@amd.com>,
	Cruise Hung <Cruise.Hung@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Sunil Khatri <sunil.khatri@amd.com>,
	Dominik Kaszewski <dominik.kaszewski@amd.com>,
	David Hildenbrand <david@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Max Kellermann <max.kellermann@ionos.com>,
	"Nysal Jan K.A." <nysal@linux.ibm.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexey Skidanov <alexey.skidanov@intel.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Vitaly Wool <vitaly.wool@konsulko.se>,
	Harry Yoo <harry.yoo@oracle.com>, Mateusz Guzik <mjguzik@gmail.com>,
	NeilBrown <neil@brown.name>, Amir Goldstein <amir73il@gmail.com>,
	Jeff Layton <jlayton@kernel.org>, Ivan Lipski <ivan.lipski@amd.com>,
	Tao Zhou <tao.zhou1@amd.com>, YiPeng Chai <YiPeng.Chai@amd.com>,
	Hawking Zhang <Hawking.Zhang@amd.com>,
	Lyude Paul <lyude@redhat.com>,
	Daniel Almeida <daniel.almeida@collabora.com>,
	Luben Tuikov <luben.tuikov@amd.com>,
	Matthew Auld <matthew.auld@intel.com>,
	Roopa Prabhu <roopa@cumulusnetworks.com>,
	Mao Zhu <zhumao001@208suo.com>,
	Shaomin Deng <dengshaomin@cdjrlc.com>,
	Charles Han <hanchunchao@inspur.com>,
	Jilin Yuan <yuanjilin@cdjrlc.com>,
	Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
	George Anthony Vernon <contact@gvernon.com>
Subject: Re: [PATCH 00/14] Assorted kernel-doc fixes
Message-ID: <aUNxq6Xk2bGzeBVO@archie.me>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
 <20251216140857.77cf0fb3@kernel.org>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="V23DYTy9ofvlaB8B"
Content-Disposition: inline
In-Reply-To: <20251216140857.77cf0fb3@kernel.org>
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eGLGT95r;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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


--V23DYTy9ofvlaB8B
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Tue, Dec 16, 2025 at 02:08:57PM -0800, Jakub Kicinski wrote:
> On Mon, 15 Dec 2025 18:38:48 +0700 Bagas Sanjaya wrote:
> > Here are assorted kernel-doc fixes for 6.19 cycle. As the name
> > implies, for the merging strategy, the patches can be taken by
> > respective maintainers to appropriate fixes branches (targetting
> > 6.19 of course) (e.g. for mm it will be mm-hotfixes).
> 
> Please submit just the relevant changes directly to respective
> subsystems. Maintainers don't have time to sort patches for you.
> You should know better.

OK, thanks!

-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUNxq6Xk2bGzeBVO%40archie.me.

--V23DYTy9ofvlaB8B
Content-Type: application/pgp-signature; name=signature.asc

-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQSSYQ6Cy7oyFNCHrUH2uYlJVVFOowUCaUNxpwAKCRD2uYlJVVFO
o1nDAP9D8xQeBKhU5vgUY1uZdEmdnOr8lzFR748Q3fszwHYA2AD+Lmk5pycZlTp2
pDdOJDlTqJohju9NNAPmvm1zT37zzwE=
=Ar/g
-----END PGP SIGNATURE-----

--V23DYTy9ofvlaB8B--
